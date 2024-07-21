import s256


def test_pair():
    code_verifier, code_challenge = s256.pair()
    assert s256.match(code_verifier, code_challenge)
