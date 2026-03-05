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
  var pendingRequests = {};
  var requestCounter = 0;

  // Called by Python (via Runtime.evaluate) to resolve/reject pending promises
  window.__recaptchaV3Callback = function(id, token, error) {
    var pending = pendingRequests[id];
    if (!pending) return;
    delete pendingRequests[id];
    if (error) {
      // Fall back to original grecaptcha.execute
      pending.fallback().then(pending.resolve).catch(pending.reject);
    } else {
      pending.resolve(token);
    }
  };

  function wrapExecute(obj) {
    if (!obj || typeof obj.execute !== 'function' || obj.__v3Intercepted) return;
    var origExecute = obj.execute.bind(obj);
    obj.execute = function(siteKey, options) {
      var id = ++requestCounter;
      return new Promise(function(resolve, reject) {
        pendingRequests[id] = {
          resolve: resolve,
          reject: reject,
          fallback: function() { return origExecute(siteKey, options); }
        };
        try {
          window.__recaptchaV3Request(JSON.stringify({
            id: id,
            siteKey: siteKey,
            action: (options && options.action) || '',
            pageUrl: window.location.href
          }));
        } catch (e) {
          // CDP binding not available -- fall back to original
          delete pendingRequests[id];
          origExecute(siteKey, options).then(resolve).catch(reject);
        }
      });
    };
    obj.__v3Intercepted = true;
  }

  // Intercept grecaptcha when Google's script assigns it to window
  var _grecaptcha = window.grecaptcha;
  Object.defineProperty(window, 'grecaptcha', {
    configurable: true,
    enumerable: true,
    get: function() { return _grecaptcha; },
    set: function(val) {
      _grecaptcha = val;
      if (val) {
        wrapExecute(val);
        if (val.enterprise) wrapExecute(val.enterprise);
      }
    }
  });

  // Handle if already set (unlikely with runImmediately, but safe)
  if (window.grecaptcha) {
    wrapExecute(window.grecaptcha);
    if (window.grecaptcha && window.grecaptcha.enterprise) {
      wrapExecute(window.grecaptcha.enterprise);
    }
  }
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

			# Register the CDP binding on the current target
			cdp_session = await self.browser_session.get_or_create_cdp_session()
			await cdp_session.cdp_client.send.Runtime.addBinding(
				params={'name': '__recaptchaV3Request'},
				session_id=cdp_session.session_id,
			)

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

			self.logger.info(
				f"RecaptchaV3Solver: Intercepted grecaptcha.execute("
				f"siteKey={payload['siteKey']}, action={payload['action']}) "
				f"on {payload['pageUrl']}"
			)

			# Spawn async task to solve and respond
			asyncio.ensure_future(
				self._solve_and_respond(
					request_id=payload['id'],
					site_key=payload['siteKey'],
					action=payload['action'],
					page_url=payload['pageUrl'],
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
		execution_context_id: int | None = None,
	) -> None:
		"""Call CapSolver API and resolve the pending Promise in page JS."""
		try:
			token = await self._call_capsolver_api(site_key, action, page_url)
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

	async def _call_capsolver_api(self, site_key: str, action: str, page_url: str) -> str:
		"""Call CapSolver API to solve reCAPTCHA v3 and return the token."""
		async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, read=65.0)) as client:
			# Create task
			self.logger.debug(f'RecaptchaV3Solver: Creating CapSolver task (siteKey={site_key}, action={action})')
			create_resp = await client.post(
				'https://api.capsolver.com/createTask',
				json={
					'clientKey': self._api_key,
					'task': {
						'type': 'ReCaptchaV3TaskProxyless',
						'websiteURL': page_url,
						'websiteKey': site_key,
						'pageAction': action,
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
					self.logger.debug(f'RecaptchaV3Solver: Token received after {(attempt + 1) * 2}s')
					return token

			raise TimeoutError('CapSolver task timed out after 60s')
