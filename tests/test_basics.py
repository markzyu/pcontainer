import common as c
import os
import unittest as t


class TestBasics(t.TestCase):
    def setUp(self):
        pass

    def test_reports_success(self):
        self.assertEqual(c.run("--cmd echo"), 0)
