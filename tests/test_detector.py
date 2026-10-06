import unittest

from scanner.detector import classify_error_response, compare_boolean_responses


class DetectorTests(unittest.TestCase):

    def test_mysql_error(self):
        body = "You have an error in your SQL syntax; check your MySQL server."
        self.assertIsNotNone(classify_error_response(body))

    def test_clean_response(self):
        self.assertIsNone(classify_error_response("Everything is fine."))

    def test_boolean_difference(self):
        baseline = "Product list product list product list"
        true = "Product list product list product list"
        false = "No products found. Completely different response."
        matched, _ = compare_boolean_responses(
            baseline, true, false, 200, 200, 200
        )
        self.assertTrue(matched)


if __name__ == "__main__":
    unittest.main()
