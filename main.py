# coding=utf-8
"""
Scripty's Dashboard

Tested with Python 3.8.
"""
import datetime
import threading
import time
import typing
import uuid

import flask_discord
import requests
from babel.numbers import format_currency
from flask import Flask, render_template, request, redirect, url_for, json, jsonify, abort, Response
from flask_sqlalchemy import SQLAlchemy
from flask_discord import DiscordOAuth2Session, requires_authorization
import stripe
import config
import pycountry
import discord_webhook

app = Flask(__name__)
session = requests.session()

if config.DEBUG:
    import os

    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    app.config["SQLALCHEMY_DATABASE_URI"] = config.DATABASE_URI_DEBUG
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = config.DATABASE_URI_PROD
app.config["DISCORD_CLIENT_ID"] = config.DISCORD_CLIENT_ID
app.config["DISCORD_CLIENT_SECRET"] = config.DISCORD_SECRET_KEY
app.config["DISCORD_REDIRECT_URI"] = config.SITE_URL + "/oauth/callback"
app.secret_key = config.SECRET_KEY
stripe.api_key = config.STRIPE_PRIVATE_API_KEY

discord = DiscordOAuth2Session(app)
db = SQLAlchemy(app)


def replace_item(obj, key, replace_value):
    """
    Recursively replace a value in a dictionary.

    :param obj: The dictionary object.
    :param key: The key that contains the value to replace.
    :param replace_value: The value to replace in the key.
    :return: The updated dictionary.
    """
    for k, v in obj.items():
        if isinstance(v, dict):
            obj[k] = replace_item(v, key, replace_value)
    if key in obj:
        obj[key] = replace_value
    return obj


# generate the product ID -> tier lookup table
PRODUCT_ID_TO_TIER = {
    tier["product_id"]: tier["level_int"] for tier in config.TIERS
}

COUNTRY_LIST = [
    {"name": country.name, "code": country.alpha_2} for country in pycountry.countries
]
COUNTRY_LIST.sort(key=lambda country: country["name"])

PROVINCE_LIST = {
    country["code"]: [province.name for province in pycountry.subdivisions.get(country_code=country["code"])]
    for country in COUNTRY_LIST
}
for country in COUNTRY_LIST:
    PROVINCE_LIST[country["code"]].sort(key=lambda province: province)

# random ID for tracking if a user completed the auth flow
AUTH_FLOW_MAP_LOCK = threading.Lock()
# AUTH_FLOW_MAP is a map of auth flow IDs to the timestamp of when they were created
# dispose of auth flow IDs that are older than 30 minutes
AUTH_FLOW_MAP: typing.Dict[str, float] = {}


# spawn a background thread that runs every 30 minutes to dispose of old auth flow IDs
def auth_flow_map_cleanup():
    while True:
        time.sleep(30 * 60)
        with AUTH_FLOW_MAP_LOCK:
            for auth_flow_id in list(AUTH_FLOW_MAP.keys()):
                if AUTH_FLOW_MAP[auth_flow_id] < (time.time() - 30 * 60):
                    del AUTH_FLOW_MAP[auth_flow_id]


threading.Thread(target=auth_flow_map_cleanup).start()


DISCORD_INVITE_SUCCESS_WEBHOOK = lambda: discord_webhook.DiscordWebhook(
    url=config.DISCORD_INVITE_SUCCESS_WEBHOOK_URL,
    username="Scripty Invites",
)


class User(db.Model):
    """
    A Discord-authenticated user.

    # Fields
    discord_id: int (primary key)
    stripe_customer_id: Option[str]
    stripe_subscription_id: Option[str]
    subscribed: bool
    """
    # noinspection SpellCheckingInspection
    __tablename__ = "users"
    discord_id = db.Column(db.BigInteger, primary_key=True)
    stripe_customer_id = db.Column(db.String)
    stripe_subscription_id = db.Column(db.String)
    subscribed = db.Column(db.Boolean)

    def __repr__(self):
        return f"<User {self.discord_id}>"


@app.route("/oauth/redirect")
def oauth_redirect():
    """
    Redirect to the Discord OAuth2 authorization page.
    """
    return discord.create_session(scope=["identify", "email"], prompt=False)


@app.route("/oauth/invite")
def oauth_invite():
    """
    Redirects to the bot invite page on Discord.
    """
    # generate the random ID for tracking if a user completed the auth flow
    # don't do this if the no_flow parameter is set to true
    if request.args.get("no_flow") != "1":
        auth_flow_id = uuid.uuid4().hex
        with AUTH_FLOW_MAP_LOCK:
            AUTH_FLOW_MAP[auth_flow_id] = time.time()
    else:
        auth_flow_id = "None"

    return discord.create_session(scope=["bot", "identify"], permissions=config.BOT_PERMISSIONS_INTEGER, data={"flow_id": auth_flow_id})


@app.route("/oauth/callback")
def oauth_callback():
    """
    Callback from the Discord OAuth2 authorization page.
    """
    cb = discord.callback()
    if flow_id := cb.get("flow_id"):
        if flow_id != "None":
            with AUTH_FLOW_MAP_LOCK:
                if flow_id in AUTH_FLOW_MAP:
                    del AUTH_FLOW_MAP[flow_id]

                    # fire the discord webhook
                    hook = DISCORD_INVITE_SUCCESS_WEBHOOK()
                    hook.set_content(
                        f"Got invited to a new server! Server ID {request.args.get('guild_id')}."
                    )
                    hook.execute()

        # if the user is coming from the bot invite, redirect to the setup page
        # be sure to add the extra query parameters discord sends us (guild_id and permissions)
        return redirect(
            url_for(
                "bot_setup",
                guild_id=request.args.get("guild_id"),
                permissions=request.args.get("permissions"),
            )
        )

    if config.DEBUG:
        user = discord.fetch_user()
        if user.id != 661660243033456652:
            discord.revoke()
            abort(403)
    return redirect("/dashboard")


@app.route("/setup")
def bot_setup():
    """
    Gives the user initial "getting started" steps to using the bot.
    """
    no_issues = True
    if (permissions := request.args.get("permissions")) is not None:
        full_permissions = int(permissions)
        # calculate if any permissions are missing
        missing_permissions = full_permissions ^ config.BOT_PERMISSIONS_INTEGER
        # if any are missing, set a flag to show the user
        missing_permissions_flag = missing_permissions != 0

        # check if critical permissions are missing
        # these include: MANAGE_WEBHOOKS, READ_MESSAGES, SEND_MESSAGES, EMBED_LINKS, CONNECT
        # humanize the names of the permissions
        major_missing = []
        if missing_permissions & 536870912:
            major_missing.append("Manage Webhooks")
        if missing_permissions & 1024:
            major_missing.append("Read Messages")
        if missing_permissions & 2048:
            major_missing.append("Send Messages")
        if missing_permissions & 16384:
            major_missing.append("Embed Links")
        if missing_permissions & 1048576:
            major_missing.append("Connect")

        warn_no_permissions = False

    else:
        missing_permissions_flag = False
        major_missing = []
        warn_no_permissions = True

    if missing_permissions_flag or len(major_missing) != 0 or warn_no_permissions:
        no_issues = False

    return render_template(
        "setup.html",
        missing_permissions_flag=missing_permissions_flag,
        major_missing=major_missing,
        warn_no_permissions=warn_no_permissions,
        no_issues=no_issues,
    )


@app.route("/dashboard")
@requires_authorization
def dashboard_index():
    return redirect(url_for("premium_index"))


@app.route("/premium")
@requires_authorization
def premium_index():
    user = discord.fetch_user()
    # fetch user from the DB
    user_db = User.query.filter_by(discord_id=user.id).first()
    if user_db is None:
        # create the user with no stripe customer ID
        user_db = User(discord_id=user.id)
        db.session.add(user_db)
        db.session.commit()

    return render_template(
        "premium.html",
        user=f"{user.username}#{user.discriminator}",
        stripe_subscription_id=user_db.stripe_subscription_id,
        tiers=config.TIERS,
    )


@app.route("/premium/stripe_redirect")
@requires_authorization
def premium_stripe_redirect():
    """
    Redirect to the Stripe billing portal.
    """
    user = discord.fetch_user()
    # fetch user from the DB
    user_db = User.query.filter_by(discord_id=user.id).first()
    if user_db is None or user_db.stripe_customer_id is None:
        abort(403)
    portal_session = stripe.billing_portal.Session.create(
        customer=user_db.stripe_customer_id,
        return_url=f"{config.SITE_URL}/premium",
    )
    return redirect(portal_session.url, 303)


@app.route("/premium/checkout", methods=["POST"])
@requires_authorization
def premium_checkout():
    user = discord.fetch_user()

    # fetch the lookup key that was sent in the request
    lookup_key = request.form["lookup_key"]

    # try to fetch the user from the DB
    user_db = User.query.filter_by(discord_id=user.id).first()
    # if it exists, check for a stripe customer ID
    if user_db is not None and user_db.stripe_customer_id is not None:
        # skip filling in details and immediately redirect to Stripe
        return redirect(url_for("premium_checkout_redirect", lookup_key=lookup_key), 303)

    price_data = stripe.Price.list(
        lookup_keys=[lookup_key],
        expand=["data.product"],
    )
    price_data = price_data.data[0]  # tosses a 500 if there was no price returned
    tier_name = price_data["product"]["name"]
    # format the price nicely
    price = "{:.2f}".format(price_data["unit_amount"] / 100)
    period = price_data["recurring"]["interval"]

    return render_template(
        "premium_checkout.html",
        user=f"{user.username}#{user.discriminator}",
        tier_name=tier_name,
        price=price,
        period=period,
        lookup_key=lookup_key,
        countries=COUNTRY_LIST
    )


@app.route("/premium/checkout/redirect", methods=["POST", "GET"])
@requires_authorization
def premium_checkout_redirect():
    user = discord.fetch_user()
    user_email = user.email

    if request.method == "GET":
        lookup_key = request.args.get("lookup_key")
    else:
        lookup_key = request.form["lookup_key"]

    # try fetching the user from the DB
    user_db = User.query.filter_by(discord_id=user.id).first()
    if user_db is None or user_db.stripe_customer_id is None:
        if request.method == "GET":
            abort(405)

        # the incoming form has all these fields
        try:
            full_name = request.form["full_name"]
            address_line_1 = request.form["address_line_1"]
            address_line_2 = request.form["address_line_2"]
            city = request.form["city"]
            province = request.form["province"]
            postal_code = request.form["postal_code"]
            country = request.form["country"]
            phone_number = request.form["phone_number"]
        except KeyError:
            abort(400)

        # create a Stripe customer from this data
        customer = stripe.Customer.create(
            email=user_email,
            name=full_name,
            address={
                "line1": address_line_1,
                "line2": address_line_2,
                "city": city,
                "state": province,
                "postal_code": postal_code,
                "country": country
            },
            phone=phone_number,
        )

        # update the existing user in the DB or create a new one if it doesn't exist
        if user_db is None:
            user_db = User(discord_id=user.id, stripe_customer_id=customer.id)
            db.session.add(user_db)
        else:
            user_db.stripe_customer_id = customer.id
        db.session.commit()

    # fetch the price data from Stripe
    price_data = stripe.Price.list(lookup_keys=[lookup_key])
    try:
        price_data_id = price_data.data[0].id
    except IndexError:
        abort(400)

    # create a checkout session
    checkout_session = stripe.checkout.Session.create(
        line_items=[
            {
                "price": price_data_id,
                "quantity": 1,
            },
        ],
        mode="subscription",
        allow_promotion_codes=True,
        success_url=config.SITE_URL + "/premium/success?session_id={CHECKOUT_SESSION_ID}",
        cancel_url=config.SITE_URL + "/premium",
        customer=user_db.stripe_customer_id,
    )

    return redirect(checkout_session.url, code=303)


@app.route("/premium/success")
@requires_authorization
def premium_success():
    checkout_session_id = request.args.get("session_id")
    checkout_session = stripe.checkout.Session.retrieve(checkout_session_id)
    # add the customer ID to the DB
    user = discord.fetch_user()
    user_db = User.query.filter_by(discord_id=user.id).first()
    if user_db is None:
        user_db = User(discord_id=user.id, stripe_customer_id=checkout_session.customer)
        db.session.add(user_db)
        db.session.commit()
    else:
        user_db.stripe_customer_id = checkout_session.customer
        db.session.commit()

    return render_template("premium_success.html")


@app.route('/stripe_webhook', methods=['POST'])
def webhook_received():
    # Retrieve the event by verifying the signature using the raw body and secret
    signature = request.headers.get('stripe-signature')
    try:
        event = stripe.Webhook.construct_event(
            payload=request.data, sig_header=signature, secret=config.STRIPE_WEBHOOK_SECRET)
        data = event['data']
    except Exception as e:
        return e
    # Get the type of webhook event sent - used to check the status of PaymentIntents.
    event_type = event['type']
    data_object = data['object']
    is_live = event["livemode"]

    print('event ' + event_type)

    discord_id = None

    if event_type == 'customer.subscription.trial_will_end':
        print('Subscription trial will end at', data_object["current_period_end"])
        print("Customer ID", data_object['customer'])
        print("Status", data_object["status"])

        # Get the user from the DB
        # If we're not in live mode, fake a user ID of 0 if none exists
        user_db = User.query.filter_by(stripe_customer_id=data_object['customer']).first()
        if user_db is None:
            if not is_live:
                discord_id = 661660243033456652
            else:
                return jsonify({'status': 'success'})
        else:
            discord_id = user_db.discord_id

    elif event_type == 'customer.subscription.created':
        print('Subscription created')
        print("Product ID", data_object['plan']['product'])
        print("Customer ID", data_object['customer'])
        print("Subscription ID", data_object["items"]["data"][0]["id"])
        print("Status", data_object["status"])

        # Get the user from the DB
        # If we're not in live mode, fake a user ID of 0 if none exists
        user_db = User.query.filter_by(stripe_customer_id=data_object['customer']).first()
        if user_db is None:
            if not is_live:
                discord_id = 661660243033456652
            else:
                return jsonify({'status': 'success'})
        else:
            # Update the user in the DB
            user_db.subscribed = True
            user_db.stripe_subscription_id = data_object["items"]["data"][0]["id"]
            db.session.commit()
            discord_id = user_db.discord_id

    elif event_type == 'customer.subscription.updated':
        print('Subscription created', event.id)
        print("Product ID", data_object['plan']['product'])
        print("Customer ID", data_object['customer'])
        print("Status", data_object["status"])

        # if data["previous_attributes"] contains only *exactly* current_period_start, current_period_end,
        # and latest_invoice, then the subscription was renewed, and we don't need to send the webhook at all
        is_renewed = False
        if len(data["previous_attributes"]) == 3:
            try:
                _ = data["previous_attributes"]["current_period_start"]
            except KeyError:
                pass
            else:
                try:
                    _ = data["previous_attributes"]["current_period_end"]
                except KeyError:
                    pass
                else:
                    try:
                        _ = data["previous_attributes"]["latest_invoice"]
                    except KeyError:
                        pass
                    else:
                        is_renewed = True

        # Get the user from the DB
        # If we're not in live mode, fake a user ID of 0 if none exists
        user_db = User.query.filter_by(stripe_customer_id=data_object['customer']).first()
        if user_db is None:
            if not is_live:
                if is_renewed:
                    # don't send the webhook if the subscription was renewed
                    print("not sending webhook because subscription was renewed")
                else:
                    # subscription was not renewed, so send the webhook
                    discord_id = 661660243033456652
            else:
                # in live mode, and no user exists, so don't send the webhook
                print("no user found for customer id", data_object['customer'])
                return jsonify({'status': 'success'})
        elif not is_renewed:
            # customer was found, and subscription was not renewed, so send the webhook
            discord_id = user_db.discord_id
        else:
            print("not sending webhook because subscription was renewed")

    elif event_type == 'customer.subscription.deleted':
        print('Subscription canceled', event.id)
        print("Product ID", data_object['plan']['product'])
        print("Customer ID", data_object['customer'])
        print("Ends at", data_object["cancel_at"])
        print("Status", data_object["status"])

        # Get the user from the DB
        # If we're not in live mode, fake a user ID of 0 if none exists
        user_db = User.query.filter_by(stripe_customer_id=data_object['customer']).first()
        if user_db is None:
            if not is_live:
                discord_id = 661660243033456652
            else:
                return jsonify({'status': 'success'})
        else:
            # Delete the user's subscription ID from the DB
            user_db.stripe_subscription_id = None
            db.session.commit()
            discord_id = user_db.discord_id

    elif event_type == "radar.early_fraud_warning":
        print('Early fraud warning', event.id)
        print("Charge ID", data_object['charge'])
        print("Reason", data_object["fraud_type"])
        if data_object["actionable"]:
            # reverse the charge and fire the cancelled subscription event
            charge = stripe.Charge.retrieve(data_object['charge'], expand=["customer", "customer.subscriptions"])
            stripe.Refund.create(charge=charge.id)
            if (subscription := charge.customer.subscriptions.data.get(0)) is not None:
                stripe.Subscription.delete(subscription.id)
                # delete the subscription ID from the DB too
                user_db = User.query.filter_by(stripe_customer_id=charge.customer.id).first()
                if user_db is not None:
                    user_db.stripe_subscription_id = None
                    db.session.commit()

    if discord_id is not None:
        print(f"Discord ID was set {discord_id}, firing bot notification")
        replace_item(event, "customer", f"cus_{discord_id}")
        session.post(
            f"{config.BOT_API_URL}/premium/stripe_webhook",
            json=event,
            headers={"Authorization": config.BOT_API_TOKEN}
        )
    else:
        print("No Discord ID found, not firing bot notification")

    return jsonify({'status': 'success'})


@app.route("/logout")
def logout():
    """
    Logout the user.
    """
    discord.revoke()
    # if there's a redir parameter, redirect to that page
    redir = request.args.get("redir")
    if redir is None:
        redir = "/"
    return redirect(redir)


@app.route("/")
def index():
    return redirect(url_for("premium_index"))


@app.route("/api/provinces")
def province_list():
    country = request.args.get("country")
    if country is None:
        abort(400)
    try:
        return jsonify(PROVINCE_LIST[country])
    except KeyError:
        abort(400)


@app.errorhandler(flask_discord.Unauthorized)
def handle_unauthorized(_):
    return redirect(url_for("oauth_redirect"))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
