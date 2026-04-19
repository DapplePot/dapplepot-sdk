import json
import logging
import threading

logger = logging.getLogger(__name__)


class ControlChannel:
    def __init__(self, tenant_id: str, client, redis_url: str = 'redis://localhost:6379'):
        self._tenant_id = tenant_id
        self._client = client
        self._redis_url = redis_url
        self._stop = threading.Event()
        self._thread = None

    def start(self) -> None:
        try:
            import redis  # noqa: F401
        except ImportError:
            logger.debug('redis not installed; control channel disabled')
            return
        self._thread = threading.Thread(target=self._listen, daemon=True, name='dp-control')
        self._thread.start()

    def _listen(self) -> None:
        try:
            import redis
            r = redis.Redis.from_url(self._redis_url)
            pubsub = r.pubsub()
            pubsub.subscribe(f'dapplepot:control:{self._tenant_id}')
            for msg in pubsub.listen():
                if self._stop.is_set():
                    break
                if msg['type'] == 'message':
                    try:
                        self._handle(json.loads(msg['data']))
                    except Exception as exc:
                        logger.warning('Control channel parse error: %s', exc)
        except Exception as exc:
            logger.warning('Control channel error: %s', exc)

    def _handle(self, cmd: dict) -> None:
        name = cmd.get('command')
        client = self._client
        if name == 'terminate_session':
            logger.info('terminate_session: %s', cmd.get('session_id'))
        elif name == 'update_tool_blocklist':
            client._tool_allowlist = set(cmd.get('blocklist', []))
            logger.info('Tool blocklist updated: %s', client._tool_allowlist)
        elif name == 'update_sample_rate':
            client._sample_rate = float(cmd.get('sample_rate', 1.0))
            logger.info('Sample rate updated: %s', client._sample_rate)
        elif name == 'update_online_checks':
            # Payload: {signal_name: action} — replaces the entire check_actions map
            check_actions = cmd.get('check_actions', {})
            client._interceptor.update_check_actions(check_actions)
            logger.info('Online check actions updated: %s', check_actions)

    def stop(self) -> None:
        self._stop.set()
