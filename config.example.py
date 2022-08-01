# coding=utf-8

# Stripe Config

# noinspection SpellCheckingInspection
STRIPE_PUBLIC_API_KEY = \
    'pk_test_kt4g09qj35ny9g3qh8j98rgj5n4q89er0hnug5q8iqg4h094qi3vpvjq34npre9a8ghnvq34ap8ehng4vq38p9hinb9q348phn9'

# noinspection SpellCheckingInspection
STRIPE_PRIVATE_API_KEY = \
    'sk_test_4q307g8yhfq34870hb3g08q47hgq3489juv083q7hng807q3h08vnq375n0g897fhcjn8704gnv03q894uerjf893q4hcn90q34'

STRIPE_WEBHOOK_SECRET = \
    'whsec_0490530302958094286791359083409670391844096702937509813590724609'

# Discord Config

# noinspection SpellCheckingInspection
DISCORD_SECRET_KEY = 'gjanperiuj4309jg43n0g409i42g0nhj'

# noinspection SpellCheckingInspection
DISCORD_CLIENT_ID = "696969696969696969"

# Bot API Config

BOT_API_URL = "http://localhost:6969"

# noinspection SpellCheckingInspection
BOT_API_TOKEN = "token"


# General Config

DEBUG = True

# noinspection SpellCheckingInspection
SITE_URL = "http://127.0.0.1:5000"

# noinspection SpellCheckingInspection
SECRET_KEY = "secret"

DATABASE_URI_DEBUG = "sqlite:////tmp/db.sqlite"
DATABASE_URI_PROD = "postgres://user:user@localhost:5432/scripty"

# noinspection SpellCheckingInspection
TIERS = [
    {
        "name": "Tier 1",
        "weekly_price": 1.00,
        "monthly_price": 4.00,
        "yearly_price": 48.00,
        "base_lookup_key": "t1",
        "product_id": "prod_g4j209ih5309j2",
        "level_int": 1,
    }
]
