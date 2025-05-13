 
import unittest
import os
from app import app, mongo
import tempfile
import jwt
from datetime import datetime, timedelta

class FlaskTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
        with app.app_context():
            mongo.db.users.drop()
            mongo.db.files.drop()
    
    def test_ops_login(self):
        # Test with no users (should fail)
        response = self.app.post('/ops/login', data={
            'email': 'ops@example.com',
            'password': 'password'
        })
        self.assertEqual(response.status_code, 401)
        
        # Create test ops user
        hashed_password = app.bcrypt.generate_password_hash('password').decode('utf-8')
        mongo.db.users.insert_one({
            'email': 'ops@example.com',
            'password': hashed_password,
            'user_type': 'ops'
        })
        
        # Test successful login
        response = self.app.post('/ops/login', data={
            'email': 'ops@example.com',
            'password': 'password'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn('token', response.json)
    
    # Add more test cases for other endpoints
    
if __name__ == '__main__':
    unittest.main()