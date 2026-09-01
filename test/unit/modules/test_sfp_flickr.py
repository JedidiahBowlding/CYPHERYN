import pytest
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from modules.sfp_flickr import sfp_flickr
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleFlickr(unittest.TestCase):

    def test_opts(self):
        module = sfp_flickr()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_flickr()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_flickr()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_flickr()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handle_event_does_not_log_api_key(self):
        module = sfp_flickr()
        module.results = {}
        module.opts = {**module.opts, 'maxpages': 1, 'per_page': 10}
        module.retrieveApiKey = Mock(return_value='super-secret-flickr-key')
        module.checkForStop = Mock(return_value=False)
        module.query = Mock(return_value=None)
        module.debug = Mock()
        event = SimpleNamespace(eventType='DOMAIN_NAME', module='fixture', data='example.com')

        module.handleEvent(event)

        logged = ' '.join(call.args[0] for call in module.debug.call_args_list)
        self.assertNotIn('super-secret-flickr-key', logged)
