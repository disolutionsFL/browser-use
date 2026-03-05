"""reCAPTCHA v3 solver watchdog — intercepts grecaptcha.execute() via CDP script injection.

Uses Page.addScriptToEvaluateOnNewDocument to inject JavaScript that overrides
grecaptcha.execute() BEFORE the page's own scripts load. When the page calls
grecaptcha.execute(), the interceptor bridges to Python via Runtime.addBinding,
which calls CapSolver's API server-side (avoiding CORS) and resolves the token
back into the page via Runtime.evaluate.

Conditionally activated only when CAPSOLVER_API_KEY env var is set.
Falls back to the original grecaptcha.execute() on any error.
"""

import asyncio
import json
import os
from typing import Any, ClassVar

import httpx
from bubus import BaseEvent
from pydantic import PrivateAttr

from browser_use.browser.events import BrowserConnectedEvent, BrowserStoppedEvent
from browser_use.browser.watchdog_base import BaseWatchdog

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
      console.warn(TAG, 'Solver error, falling back to original execute for id=' + id);
      // Fall back to original grecaptcha.execute
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
	"""Intercepts grecaptcha.execute() and solves reCAPTCHA v3 via CapSolver API.

	Uses CDP Page.addScriptToEvaluateOnNewDocument to inject an interceptor
	before page scripts load, and Runtime.addBinding to bridge calls from
	page JavaScript to Python for server-side API calls (avoiding CORS).
	"""

	LISTENS_TO: ClassVar[list[type[BaseEvent]]] = [
		BrowserConnectedEvent,
		BrowserStoppedEvent,
	]
	EMITS: ClassVar[list[type[BaseEvent]]] = []

	# --- private state ---
	_api_key: str = PrivateAttr(default='')
	_script_id: str | None = PrivateAttr(default=None)
	_active: bool = PrivateAttr(default=False)
	_cdp_handlers_registered: bool = PrivateAttr(default=False)

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

			# Inject the interceptor script (runs before page JS on every navigation)
			self._script_id = await self.browser_session._cdp_add_init_script(_INTERCEPTOR_JS)

			self._active = True
			self._cdp_handlers_registered = True
			self.logger.info('RecaptchaV3Solver: Interceptor installed (grecaptcha.execute will be routed through CapSolver)')
		except Exception:
			self.logger.exception('RecaptchaV3Solver: Failed to install interceptor')

	async def on_BrowserStoppedEvent(self, event: BrowserStoppedEvent) -> None:
		"""Clean up state when browser disconnects."""
		if self._active and self._script_id:
			try:
				await self.browser_session._cdp_remove_init_script(self._script_id)
			except Exception:
				pass  # Browser is stopping, CDP may already be gone
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

			# Handle self-test from injected JS
			if payload.get('siteKey') == '__selftest__':
				self.logger.info('RecaptchaV3Solver: Self-test PASSED -- CDP binding bridge is working')
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
		"""Call CapSolver API and resolve the pending Promise in page JS."""
		try:
			token = await self._call_capsolver_api(site_key, action, page_url, is_enterprise)
			escaped_token = json.dumps(token)
			js = f'window.__recaptchaV3Callback({request_id}, {escaped_token}, null)'
			self.logger.info(f'RecaptchaV3Solver: Token received, resolving promise (request={request_id})')
		except Exception as e:
			escaped_error = json.dumps(str(e))
			js = f'window.__recaptchaV3Callback({request_id}, null, {escaped_error})'
			self.logger.error(f'RecaptchaV3Solver: Failed to solve, falling back to original: {e}')

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
			self.logger.exception('RecaptchaV3Solver: Failed to evaluate callback in page context')

	async def _call_capsolver_api(self, site_key: str, action: str, page_url: str, is_enterprise: bool = False) -> str:
		"""Call CapSolver API to solve reCAPTCHA v3 and return the token.

		Uses a fallback strategy: when grecaptcha.execute() is detected (not explicitly
		Enterprise), tries Enterprise first because sites can load enterprise.js which
		aliases grecaptcha.execute() = grecaptcha.enterprise.execute(). If Enterprise
		fails, falls back to standard v3.
		"""
		# When JS explicitly detected Enterprise, use that. Otherwise try Enterprise
		# first (covers the alias case), then fall back to standard.
		if is_enterprise:
			task_types = ['ReCaptchaV3EnterpriseTaskProxyless']
		else:
			task_types = ['ReCaptchaV3EnterpriseTaskProxyless', 'ReCaptchaV3TaskProxyless']

		last_error = None
		for task_type in task_types:
			try:
				token = await self._create_and_poll_task(task_type, site_key, action, page_url)
				return token
			except RuntimeError as e:
				last_error = e
				if len(task_types) > 1:
					self.logger.info(f'RecaptchaV3Solver: {task_type} failed ({e}), trying next type...')
				continue

		raise last_error or RuntimeError('All CapSolver task types failed')

	async def _create_and_poll_task(self, task_type: str, site_key: str, action: str, page_url: str) -> str:
		"""Create a CapSolver task and poll for the result."""
		async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, read=65.0)) as client:
			self.logger.info(f'RecaptchaV3Solver: Creating CapSolver task (type={task_type}, siteKey={site_key}, action={action})')
			create_resp = await client.post(
				'https://api.capsolver.com/createTask',
				json={
					'clientKey': self._api_key,
					'task': {
						'type': task_type,
						'websiteURL': page_url,
						'websiteKey': site_key,
						'pageAction': action,
						'minScore': 0.9,
					},
				},
			)
			create_data = create_resp.json()

			if create_data.get('errorId'):
				raise RuntimeError(f"CapSolver createTask error: {create_data.get('errorDescription', 'unknown')}")

			task_id = create_data['taskId']
			self.logger.debug(f'RecaptchaV3Solver: Task created (taskId={task_id}), polling for result...')

			# Poll for result (up to 60 seconds)
			for attempt in range(30):
				await asyncio.sleep(2)
				result_resp = await client.post(
					'https://api.capsolver.com/getTaskResult',
					json={
						'clientKey': self._api_key,
						'taskId': task_id,
					},
				)
				result_data = result_resp.json()

				if result_data.get('errorId'):
					raise RuntimeError(f"CapSolver getTaskResult error: {result_data.get('errorDescription', 'unknown')}")

				if result_data.get('status') == 'ready':
					token = result_data['solution']['gRecaptchaResponse']
					self.logger.info(f'RecaptchaV3Solver: Token received via {task_type} after {(attempt + 1) * 2}s')
					return token

			raise TimeoutError(f'CapSolver {task_type} task timed out after 60s')
