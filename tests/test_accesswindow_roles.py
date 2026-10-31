import unittest
from app import app

class AccessWindowRoleTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True)
        self.client = app.test_client()

    def login_as(self, username, role):
        with self.client.session_transaction() as sess:
            sess['username'] = username
            sess['role'] = role
            sess['csrf_token'] = 'test-token'

    def test_requester_cannot_approve(self):
        self.login_as('bob', 'requester')
        response = self.client.post('/request/TEST123/approve', data={'csrf_token': 'test-token'})
        self.assertEqual(response.status_code, 403)

    def test_requester_cannot_revoke(self):
        self.login_as('bob', 'requester')
        response = self.client.post('/grant/TEST123/revoke', data={'csrf_token': 'test-token'})
        self.assertEqual(response.status_code, 403)

    def test_admin_cannot_submit_as_requester(self):
        self.login_as('admin', 'admin')
        response = self.client.post('/request', data={
            'csrf_token': 'test-token', 'service': 'web', 'minutes': '5', 'reason': 'test'
        })
        self.assertEqual(response.status_code, 403)

    def test_post_requires_csrf_token(self):
        self.login_as('bob', 'requester')
        response = self.client.post('/request', data={'service': 'web', 'minutes': '5', 'reason': 'test'})
        self.assertEqual(response.status_code, 400)

if __name__ == '__main__':
    unittest.main()
