import flask


def test_python_runs():
    assert 1 + 1 == 2


def test_flask_imports():
    app = flask.Flask(__name__)
    assert app is not None