import os


def get_password():
    # This function fetches a password from the environment.
    return os.environ["PASSWORD"]
