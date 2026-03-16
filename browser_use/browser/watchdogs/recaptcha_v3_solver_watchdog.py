"""reCAPTCHA v3 solver watchdog — intercepts grecaptcha.execute() via CDP script injection.

Uses Page.addScriptToEvaluateOnNewDocument to inject JavaScript that overrides
grecaptcha.execute() BEFORE the page's own scripts load. When the page calls
grecaptcha.execute(), the interceptor bridges to Python via Runtime.addBinding.

Multi-layer strategy:
1. Stealth patches — fix browser fingerprint leaks (WebGL SwiftShader, empty
   plugins, navigator.webdriver) that tank reCAPTCHA v3 scores on headless/xvfb.
2. Background behavior simulation — continuous mouse/scroll events via CDP
   Input domain (isTrusted=true) from browser connect onwards.
3. CapSolver API — primary solver, requests high-score token server-side.
4. Original execute fallback — if CapSolver fails, calls original
   grecaptcha.execute() which benefits from layers 1+2.

Conditionally activated only when CAPSOLVER_API_KEY env var is set.
"""

import asyncio
import json
import os
import random
from typing import Any, ClassVar

import httpx
from bubus import BaseEvent
from pydantic import PrivateAttr

from browser_use.browser.events import BrowserConnectedEvent, BrowserStoppedEvent
from browser_use.browser.watchdog_base import BaseWatchdog

# Browser stealth patches injected BEFORE page scripts load.
# Addresses the fingerprint signals that reCAPTCHA v3 uses for scoring:
# - navigator.webdriver (automation flag)
# - WebGL renderer (SwiftShader = virtual display)
# - navigator.plugins (empty = headless)
# - navigator.languages, chrome.runtime, permissions API
_STEALTH_JS = r"""(function() {
  var TAG = '[BrowserStealth]';

  // 1. navigator.webdriver -> undefined
  // Chrome flag --disable-blink-features=AutomationControlled should handle this,
  // but belt-and-suspenders for reCAPTCHA v3's deep checks.
  try {
    Object.defineProperty(navigator, 'webdriver', {
      get: function() { return undefined; },
      configurable: true
    });
  } catch(e) {}

  // 2. WebGL renderer spoofing — SwiftShader (xvfb) is a dead giveaway.
  // Spoof to a common integrated GPU that won't raise flags.
  try {
    var VENDOR = 'Intel Inc.';
    var RENDERER = 'Intel Iris OpenGL Engine';
    var origGetParameter = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function(param) {
      if (param === 37445) return VENDOR;   // UNMASKED_VENDOR_WEBGL
      if (param === 37446) return RENDERER;  // UNMASKED_RENDERER_WEBGL
      return origGetParameter.call(this, param);
    };
    if (typeof WebGL2RenderingContext !== 'undefined') {
      var origGetParameter2 = WebGL2RenderingContext.prototype.getParameter;
      WebGL2RenderingContext.prototype.getParameter = function(param) {
        if (param === 37445) return VENDOR;
        if (param === 37446) return RENDERER;
        return origGetParameter2.call(this, param);
      };
    }
  } catch(e) {}

  // 3. navigator.plugins — headless Chrome has 0 plugins, real Chrome has 5.
  // Create a minimal PluginArray-like object.
  try {
    var fakePlugins = {
      0: {name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format'},
      1: {name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: ''},
      2: {name: 'Native Client', filename: 'internal-nacl-plugin', description: ''},
      length: 3,
      item: function(i) { return this[i] || null; },
      namedItem: function(name) {
        for (var i = 0; i < this.length; i++) { if (this[i].name === name) return this[i]; }
        return null;
      },
      refresh: function() {}
    };
    Object.defineProperty(navigator, 'plugins', {
      get: function() { return fakePlugins; },
      configurable: true
    });
  } catch(e) {}

  // 4. navigator.mimeTypes — complement to plugins
  try {
    var fakeMimeTypes = {
      0: {type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format', enabledPlugin: null},
      length: 1,
      item: function(i) { return this[i] || null; },
      namedItem: function(name) {
        for (var i = 0; i < this.length; i++) { if (this[i].type === name) return this[i]; }
        return null;
      }
    };
    Object.defineProperty(navigator, 'mimeTypes', {
      get: function() { return fakeMimeTypes; },
      configurable: true
    });
  } catch(e) {}

  // 5. navigator.languages (ensure non-empty)
  try {
    Object.defineProperty(navigator, 'languages', {
      get: function() { return ['en-US', 'en']; },
      configurable: true
    });
  } catch(e) {}

  // 6. window.chrome — must exist in real Chrome
  try {
    if (!window.chrome) window.chrome = {};
    if (!window.chrome.runtime) {
      window.chrome.runtime = {
        connect: function() {},
        sendMessage: function() {}
      };
    }
  } catch(e) {}

  // 7. Permissions API — prevent leak of automation-granted permissions
  try {
    var origQuery = navigator.permissions.query.bind(navigator.permissions);
    navigator.permissions.query = function(desc) {
      if (desc.name === 'notifications') {
        return Promise.resolve({state: Notification.permission, onchange: null});
      }
      return origQuery(desc);
    };
  } catch(e) {}

  // 8. navigator.connection — headless often missing this
  try {
    if (!navigator.connection) {
      Object.defineProperty(navigator, 'connection', {
        get: function() {
          return {
            effectiveType: '4g',
            rtt: 50,
            downlink: 10,
            saveData: false
          };
        },
        configurable: true
      });
    }
  } catch(e) {}

  console.warn(TAG, 'Stealth patches applied');
})();"""

# JavaScript interceptor injected via Page.addScriptToEvaluateOnNewDocument.
# Runs before any page script (runImmediately=True), intercepting grecaptcha.execute()
# when Google's reCAPTCHA v3 script assigns it to window.grecaptcha.
_INTERCEPTOR_JS = r"""(function() {
  var TAG = '[RecaptchaV3Interceptor]';
  var pendingRequests = {};
  var requestCounter = 0;

  console.warn(TAG, 'Script loaded, setting up interceptor');

  // Called by Python (via Runtime.evaluate) to resolve/reject pending promises
  window.__recaptchaV3Callback = function(id, token, error) {
    var pending = pendingRequests[id];
    if (!pending) return;
    delete pendingRequests[id];
    if (error) {
      if (error === '__behavior_enhanced__') {
        console.warn(TAG, 'Using behavior-enhanced original execute for id=' + id);
      } else {
        console.warn(TAG, 'Solver error, falling back to original execute for id=' + id + ': ' + error);
      }
      // Use original grecaptcha.execute (behavior simulation already done via CDP)
      pending.fallback().then(pending.resolve).catch(pending.reject);
    } else {
      console.warn(TAG, 'Token received from solver for id=' + id);
      pending.resolve(token);
    }
  };

  function wrapExecute(obj, isEnterprise) {
    if (!obj || typeof obj.execute !== 'function' || obj.__v3Intercepted) return;
    console.warn(TAG, 'Wrapping grecaptcha' + (isEnterprise ? '.enterprise' : '') + '.execute()');
    var origExecute = obj.execute.bind(obj);
    obj.execute = function(siteKey, options) {
      var id = ++requestCounter;
      console.warn(TAG, 'grecaptcha' + (isEnterprise ? '.enterprise' : '') + '.execute() intercepted! id=' + id + ' siteKey=' + siteKey + ' action=' + ((options && options.action) || ''));
      return new Promise(function(resolve, reject) {
        pendingRequests[id] = {
          resolve: resolve,
          reject: reject,
          fallback: function() { return origExecute(siteKey, options); }
        };
        var bindingAvailable = typeof window.__recaptchaV3Request === 'function';
        console.warn(TAG, 'CDP binding available: ' + bindingAvailable);
        if (!bindingAvailable) {
          console.warn(TAG, 'No CDP binding, falling back to original execute');
          delete pendingRequests[id];
          origExecute(siteKey, options).then(resolve).catch(reject);
          return;
        }
        try {
          window.__recaptchaV3Request(JSON.stringify({
            id: id,
            siteKey: siteKey,
            action: (options && options.action) || '',
            pageUrl: window.location.href,
            isEnterprise: !!isEnterprise
          }));
          console.warn(TAG, 'CDP binding called successfully for id=' + id);
        } catch (e) {
          // CDP binding threw -- fall back to original
          console.warn(TAG, 'CDP binding threw: ' + e.message + ', falling back');
          delete pendingRequests[id];
          origExecute(siteKey, options).then(resolve).catch(reject);
        }
      });
    };
    obj.__v3Intercepted = true;
  }

  // Watch for .execute being added to an object AFTER it's created.
  // Google's reCAPTCHA v3 often does: window.grecaptcha = {} first,
  // then adds .execute as a property later. Our window setter fires
  // on the first assignment but .execute doesn't exist yet.
  function watchForExecute(obj, isEnterprise) {
    if (!obj || obj.__v3Watched) return;
    obj.__v3Watched = true;

    // If execute already exists as a function, wrap it now
    if (typeof obj.execute === 'function') {
      console.warn(TAG, 'execute already exists on object, wrapping now (enterprise=' + !!isEnterprise + ')');
      wrapExecute(obj, isEnterprise);
      return;
    }

    console.warn(TAG, 'execute not yet on object, setting up defineProperty watcher (enterprise=' + !!isEnterprise + ')');

    // Watch for execute being defined later via property assignment
    var _currentExecute = obj.execute;
    try {
      Object.defineProperty(obj, 'execute', {
        configurable: true,
        enumerable: true,
        get: function() { return _currentExecute; },
        set: function(fn) {
          console.warn(TAG, 'execute property setter fired, type=' + typeof fn + ' (enterprise=' + !!isEnterprise + ')');
          _currentExecute = fn;
          if (typeof fn === 'function' && !obj.__v3Intercepted) {
            // execute was just defined! Convert back to normal property and wrap.
            delete obj.execute;
            obj.execute = fn;
            wrapExecute(obj, isEnterprise);
          }
        }
      });
      console.warn(TAG, 'defineProperty watcher installed on object');
    } catch (e) {
      console.warn(TAG, 'defineProperty failed: ' + e.message + ', falling back to polling');
      // defineProperty failed -- fall back to polling
      var pollCount = 0;
      var pollInterval = setInterval(function() {
        pollCount++;
        if (typeof obj.execute === 'function' && !obj.__v3Intercepted) {
          console.warn(TAG, 'Polling found execute at attempt ' + pollCount);
          clearInterval(pollInterval);
          wrapExecute(obj, isEnterprise);
        }
        if (pollCount > 50) clearInterval(pollInterval); // give up after 10s
      }, 200);
    }
  }

  // Intercept grecaptcha when Google's script assigns it to window
  var _grecaptcha = window.grecaptcha;
  Object.defineProperty(window, 'grecaptcha', {
    configurable: true,
    enumerable: true,
    get: function() { return _grecaptcha; },
    set: function(val) {
      console.warn(TAG, 'window.grecaptcha setter fired, type=' + typeof val, val ? ('keys=' + Object.keys(val).join(',')) : '');
      _grecaptcha = val;
      if (val) {
        watchForExecute(val, false);
        if (val.enterprise) {
          console.warn(TAG, 'Also watching val.enterprise');
          watchForExecute(val.enterprise, true);
        }
      }
    }
  });
  console.warn(TAG, 'window.grecaptcha property trap installed');

  // Handle if already set (unlikely with runImmediately, but safe)
  if (window.grecaptcha) {
    console.warn(TAG, 'grecaptcha already exists at script load time!');
    watchForExecute(window.grecaptcha, false);
    if (window.grecaptcha && window.grecaptcha.enterprise) {
      watchForExecute(window.grecaptcha.enterprise, true);
    }
  }

  // Self-test: verify CDP binding is reachable
  setTimeout(function() {
    var available = typeof window.__recaptchaV3Request === 'function';
    console.warn(TAG, 'Self-test (1s): CDP binding available = ' + available);
    if (available) {
      try {
        window.__recaptchaV3Request(JSON.stringify({id: 0, siteKey: '__selftest__', action: '__selftest__', pageUrl: window.location.href}));
        console.warn(TAG, 'Self-test: binding call succeeded');
      } catch (e) {
        console.warn(TAG, 'Self-test: binding call threw: ' + e.message);
      }
    }
  }, 1000);
})();"""


class RecaptchaV3SolverWatchdog(BaseWatchdog):
	"""Intercepts grecaptcha.execute() and improves reCAPTCHA v3 scoring.

	Multi-layer approach: stealth fingerprint patches + continuous behavior
	simulation + CapSolver API tokens + original execute fallback.
	"""

	LISTENS_TO: ClassVar[list[type[BaseEvent]]] = [
		BrowserConnectedEvent,
		BrowserStoppedEvent,
	]
	EMITS: ClassVar[list[type[BaseEvent]]] = []

	# --- private state ---
	_api_key: str = PrivateAttr(default='')
	_stealth_script_id: str | None = PrivateAttr(default=None)
	_script_id: str | None = PrivateAttr(default=None)
	_active: bool = PrivateAttr(default=False)
	_cdp_handlers_registered: bool = PrivateAttr(default=False)
	_bg_mouse_task: Any = PrivateAttr(default=None)  # asyncio.Task for background simulation
	_mouse_x: float = PrivateAttr(default=500.0)
	_mouse_y: float = PrivateAttr(default=400.0)

	def model_post_init(self, __context: Any) -> None:
		self._api_key = os.getenv('CAPSOLVER_API_KEY', '')

	# ------------------------------------------------------------------
	# Event handlers
	# ------------------------------------------------------------------

	async def on_BrowserConnectedEvent(self, event: BrowserConnectedEvent) -> None:
		"""Register CDP binding and inject grecaptcha.execute() interceptor."""
		if not self._api_key:
			self.logger.debug('RecaptchaV3Solver: No CAPSOLVER_API_KEY set, skipping')
			return

		if self._cdp_handlers_registered:
			self.logger.debug('RecaptchaV3Solver: CDP handlers already registered, skipping')
			return

		try:
			# Register event handler on root CDP client (catches events from all targets)
			self.browser_session.cdp_client.register.Runtime.bindingCalled(self._on_binding_called)

			# Enable Runtime domain (required for Runtime.bindingCalled events to be dispatched)
			cdp_session = await self.browser_session.get_or_create_cdp_session()
			await cdp_session.cdp_client.send.Runtime.enable(
				session_id=cdp_session.session_id,
			)
			self.logger.debug('RecaptchaV3Solver: Runtime domain enabled')

			# Register the CDP binding on the current target
			await cdp_session.cdp_client.send.Runtime.addBinding(
				params={'name': '__recaptchaV3Request'},
				session_id=cdp_session.session_id,
			)
			self.logger.debug('RecaptchaV3Solver: CDP binding registered')

			# Inject stealth patches first (must run before reCAPTCHA script loads)
			self._stealth_script_id = await self.browser_session._cdp_add_init_script(_STEALTH_JS)
			self.logger.debug('RecaptchaV3Solver: Stealth patches injected')

			# Inject the interceptor script (runs before page JS on every navigation)
			self._script_id = await self.browser_session._cdp_add_init_script(_INTERCEPTOR_JS)

			self._active = True
			self._cdp_handlers_registered = True

			# Start continuous background mouse simulation
			self._bg_mouse_task = asyncio.ensure_future(self._background_mouse_loop())

			self.logger.info('RecaptchaV3Solver: Stealth patches + interceptor + background behavior simulation started')
		except Exception:
			self.logger.exception('RecaptchaV3Solver: Failed to install interceptor')

	async def on_BrowserStoppedEvent(self, event: BrowserStoppedEvent) -> None:
		"""Clean up state when browser disconnects."""
		# Stop background mouse simulation
		if self._bg_mouse_task and not self._bg_mouse_task.done():
			self._bg_mouse_task.cancel()
			self._bg_mouse_task = None

		if self._active:
			for sid in (self._stealth_script_id, self._script_id):
				if sid:
					try:
						await self.browser_session._cdp_remove_init_script(sid)
					except Exception:
						pass  # Browser is stopping, CDP may already be gone
		self._stealth_script_id = None
		self._script_id = None
		self._active = False
		self._cdp_handlers_registered = False

	# ------------------------------------------------------------------
	# CDP binding callback
	# ------------------------------------------------------------------

	def _on_binding_called(self, event_data: dict, session_id: str | None) -> None:
		"""Handle Runtime.bindingCalled events from the injected interceptor."""
		if event_data.get('name') != '__recaptchaV3Request':
			return

		try:
			payload = json.loads(event_data['payload'])
			execution_context_id = event_data.get('executionContextId')

			# Handle self-test from injected JS (fires per-frame, log at debug after first)
			if payload.get('siteKey') == '__selftest__':
				if not hasattr(self, '_selftest_passed'):
					self._selftest_passed = True
					self.logger.info('RecaptchaV3Solver: Self-test PASSED -- CDP binding bridge is working')
				else:
					self.logger.debug('RecaptchaV3Solver: Self-test PASSED (frame)')
				return

			is_enterprise = payload.get('isEnterprise', False)
			self.logger.info(
				f"RecaptchaV3Solver: Intercepted grecaptcha{'enterprise.' if is_enterprise else '.'}"
				f"execute(siteKey={payload['siteKey']}, action={payload['action']}) "
				f"on {payload['pageUrl']}"
			)

			# Spawn async task to solve and respond
			asyncio.ensure_future(
				self._solve_and_respond(
					request_id=payload['id'],
					site_key=payload['siteKey'],
					action=payload['action'],
					page_url=payload['pageUrl'],
					is_enterprise=is_enterprise,
					execution_context_id=execution_context_id,
				)
			)
		except Exception:
			self.logger.exception('RecaptchaV3Solver: Error parsing binding call')

	# ------------------------------------------------------------------
	# Solver logic
	# ------------------------------------------------------------------

	async def _solve_and_respond(
		self,
		request_id: int,
		site_key: str,
		action: str,
		page_url: str,
		is_enterprise: bool = False,
		execution_context_id: int | None = None,
	) -> None:
		"""Try CapSolver API first for a high-score token, fall back to stealth execute.

		Strategy:
		1. CapSolver API generates a token server-side with a high score (0.7-0.9).
		   This bypasses BB8's browser fingerprint issues entirely.
		2. If CapSolver fails, fall back to stealth-enhanced original execute which
		   runs in the patched browser with spoofed fingerprints + behavior simulation.

		Why CapSolver first: The stealth-patched browser on BB8 (xvfb + SwiftShader)
		consistently gets low reCAPTCHA v3 scores despite fingerprint spoofing. Google's
		deep checks see through the patches. CapSolver tokens are generated on clean
		infrastructure and reliably score high enough to pass.
		"""
		# Final burst of mouse activity (background loop has been running since connect)
		await self._simulate_mouse_burst()

		# Primary: CapSolver API token
		token = None
		try:
			token = await self._call_capsolver_api(site_key, action, page_url, is_enterprise)
			self.logger.info(
				f'RecaptchaV3Solver: Got CapSolver token for request={request_id} '
				f'(len={len(token)}), resolving Promise directly'
			)
		except Exception:
			self.logger.warning(
				f'RecaptchaV3Solver: CapSolver API failed for request={request_id}, '
				f'falling back to stealth-enhanced original execute'
			)

		if token:
			# Resolve the intercepted Promise with the CapSolver token directly
			escaped_token = token.replace("'", "\\'")
			js = f"window.__recaptchaV3Callback({request_id}, '{escaped_token}', null)"
		else:
			# Fallback: let original grecaptcha.execute() run in stealth-patched browser
			js = f"window.__recaptchaV3Callback({request_id}, null, '__behavior_enhanced__')"

		self.logger.info(
			f'RecaptchaV3Solver: Resolving request={request_id} via '
			f'{"CapSolver token" if token else "stealth-enhanced original execute"} '
			f'(page={page_url})'
		)

		try:
			cdp_session = await self.browser_session.get_or_create_cdp_session()
			params: dict[str, Any] = {'expression': js}
			if execution_context_id is not None:
				params['contextId'] = execution_context_id
			await cdp_session.cdp_client.send.Runtime.evaluate(
				params=params,
				session_id=cdp_session.session_id,
			)
		except Exception:
			self.logger.exception(
				f'RecaptchaV3Solver: Failed to evaluate callback for request={request_id} '
				f'(execution context likely destroyed by page navigation)'
			)

	async def _background_mouse_loop(self) -> None:
		"""Continuous background mouse simulation running from browser connect.

		Dispatches gentle, periodic mouse movements via CDP so that reCAPTCHA v3
		sees sustained human-like behavior throughout the entire page session,
		not just a burst at execute() time.
		"""
		self.logger.info('RecaptchaV3Solver: Background mouse simulation started')
		event_count = 0
		try:
			while self._active:
				# Wait 0.5-2.5 seconds between movements (natural idle behavior)
				await asyncio.sleep(random.uniform(0.5, 2.5))

				if not self._active:
					break

				try:
					cdp_session = await self.browser_session.get_or_create_cdp_session()
					sid = cdp_session.session_id

					# Small organic movement (Brownian motion)
					self._mouse_x += random.gauss(0, 30)
					self._mouse_y += random.gauss(0, 20)
					self._mouse_x = max(10, min(self._mouse_x, 1900))
					self._mouse_y = max(10, min(self._mouse_y, 1060))

					await cdp_session.cdp_client.send.Input.dispatchMouseEvent(
						params={
							'type': 'mouseMoved',
							'x': round(self._mouse_x),
							'y': round(self._mouse_y),
						},
						session_id=sid,
					)
					event_count += 1

					# Occasional scroll (every ~8-15 events)
					if event_count % random.randint(8, 15) == 0:
						try:
							await cdp_session.cdp_client.send.Input.dispatchMouseEvent(
								params={
									'type': 'mouseWheel',
									'x': round(self._mouse_x),
									'y': round(self._mouse_y),
									'deltaX': 0,
									'deltaY': random.choice([-60, -30, 30, 60]),
								},
								session_id=sid,
							)
						except Exception:
							pass

				except asyncio.CancelledError:
					raise
				except Exception:
					# CDP session may be invalid during navigation, just retry next loop
					await asyncio.sleep(1)

		except asyncio.CancelledError:
			pass
		finally:
			self.logger.info(f'RecaptchaV3Solver: Background mouse simulation stopped ({event_count} events dispatched)')

	async def _simulate_mouse_burst(self) -> None:
		"""Final burst of mouse activity before calling grecaptcha.execute().

		Supplements the continuous background simulation with a quick burst
		of purposeful movement toward the submit area.
		"""
		try:
			cdp_session = await self.browser_session.get_or_create_cdp_session()
			sid = cdp_session.session_id

			# Quick burst: move toward submit button area
			target_x = random.uniform(400, 700)
			target_y = random.uniform(500, 700)
			start_x, start_y = self._mouse_x, self._mouse_y
			steps = random.randint(5, 8)

			for i in range(steps):
				progress = (i + 1) / steps
				ease = 1 - (1 - progress) ** 2
				cx = start_x + (target_x - start_x) * ease + random.gauss(0, 3)
				cy = start_y + (target_y - start_y) * ease + random.gauss(0, 3)

				await cdp_session.cdp_client.send.Input.dispatchMouseEvent(
					params={'type': 'mouseMoved', 'x': round(cx), 'y': round(cy)},
					session_id=sid,
				)
				await asyncio.sleep(random.uniform(0.03, 0.08))

			self._mouse_x, self._mouse_y = target_x, target_y

		except Exception:
			pass  # Don't block the execute flow

	async def _call_capsolver_api(self, site_key: str, action: str, page_url: str, is_enterprise: bool = False) -> str:
		"""Call CapSolver API to solve reCAPTCHA v3 and return the token.

		Tries standard v3 first (cheaper), then Enterprise as fallback.
		When JS explicitly detected Enterprise, only tries Enterprise.

		NOTE: reCAPTCHA v3 scores depend on browser behavior signals (mouse
		movements, scrolling, typing patterns). API-based solvers generate tokens
		without these signals, so Google may assign low scores. If the site's
		server requires a high score, API-generated tokens may be rejected even
		though CapSolver reports the task as "Success".
		"""
		if is_enterprise:
			task_types = ['ReCaptchaV3EnterpriseTaskProxyLess']
		else:
			# Standard first (cheaper: $0.001 vs $0.003), Enterprise as fallback
			task_types = ['ReCaptchaV3TaskProxyLess', 'ReCaptchaV3EnterpriseTaskProxyLess']

		last_error = None
		for task_type in task_types:
			try:
				token = await self._solve_with_get_token(task_type, site_key, action, page_url)
				self.logger.info(
					f'RecaptchaV3Solver: Token received via {task_type} '
					f'(len={len(token)}, prefix={token[:20]}...)'
				)
				return token
			except Exception as e:
				last_error = e
				if len(task_types) > 1:
					self.logger.info(f'RecaptchaV3Solver: {task_type} failed ({e}), trying next type...')
				continue

		raise last_error or RuntimeError('All CapSolver task types failed')

	async def _solve_with_get_token(self, task_type: str, site_key: str, action: str, page_url: str) -> str:
		"""Use CapSolver's getToken endpoint for direct token retrieval."""
		async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, read=120.0)) as client:
			self.logger.info(f'RecaptchaV3Solver: Calling getToken (type={task_type}, siteKey={site_key}, action={action})')
			resp = await client.post(
				'https://api.capsolver.com/getToken',
				json={
					'clientKey': self._api_key,
					'task': {
						'type': task_type,
						'websiteURL': page_url,
						'websiteKey': site_key,
						'pageAction': action,
					},
				},
			)
			data = resp.json()

			if data.get('errorId'):
				raise RuntimeError(f"CapSolver getToken error: {data.get('errorDescription', 'unknown')}")

			if data.get('status') != 'ready':
				raise RuntimeError(f"CapSolver getToken not ready: status={data.get('status')}")

			token = data['solution']['gRecaptchaResponse']
			return token
