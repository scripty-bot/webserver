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
import jwt
import oauthlib.oauth2.rfc6749.errors
import requests
from babel.numbers import format_currency
from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_discord import DiscordOAuth2Session, requires_authorization
import stripe
from sqlalchemy import text

import config
import pycountry
import discord_webhook
from werkzeug.exceptions import BadRequest, MethodNotAllowed, Forbidden

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
    subscribed = db.Column(db.Boolean, default=False, nullable=False, server_default=text("false"))
    free_trial_pending = db.Column(db.Boolean, default=False, nullable=False, server_default=text("false"))

    def __repr__(self):
        return f"<User {self.discord_id}>"


@app.route("/oauth/redirect")
def oauth_redirect():
    """
    Redirect to the Discord OAuth2 authorization page.
    """
    return discord.create_session(scope=["identify", "email"])


@app.route("/oauth/invite")
def oauth_invite():
    """
    Redirects to the bot invite page on Discord.
    """
    oauth_data = {}
    scopes = ["bot", "identify"]

    # generate the random ID for tracking if a user completed the auth flow
    # don't do this if the no_flow parameter is set to true
    if request.args.get("no_flow") != "1":
        auth_flow_id = uuid.uuid4().hex
        with AUTH_FLOW_MAP_LOCK:
            AUTH_FLOW_MAP[auth_flow_id] = time.time()
    else:
        auth_flow_id = "None"
    oauth_data["flow_id"] = auth_flow_id

    # check if the user requested being added to the support server
    if request.args.get("support_server") == "1":
        # additionally request the guilds.join scope
        scopes.append("guilds.join")
        # and add a query parameter to the redirect URL
        oauth_data["support_server"] = "1"
    else:
        oauth_data["support_server"] = "0"

    return discord.create_session(scope=scopes, permissions=config.BOT_PERMISSIONS_INTEGER,
                                  data=oauth_data)


@app.route("/oauth/callback")
def oauth_callback():
    """
    Callback from the Discord OAuth2 authorization page.
    """
    try:
        cb = discord.callback()
    except (jwt.exceptions.PyJWTError, oauthlib.oauth2.rfc6749.errors.OAuth2Error):
        raise BadRequest("Invalid OAuth2 data: don't mess with the URL parameters!")

    # check if the user requested being added to the support server
    if cb.get("support_server") == "1":
        # add the user to the support server
        discord.fetch_user().add_to_guild(config.SUPPORT_SERVER_ID)

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
            raise Forbidden("In test mode, rejecting all other users except the bot owner.")
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

    # fetch the currency from what was passed in the URL query parameters
    currency = request.args.get("currency", "usd")

    # fetch products from stripe
    products = stripe.Product.list()
    # filter to only those with a metadata field of "tier"
    products = [product for product in products.auto_paging_iter() if "tier" in product.metadata]
    # sort by tier, lowest to highest
    products.sort(key=lambda product: int(product.metadata["tier"]))
    # fetch the prices for each product, depending on the currency
    prices = []
    for product in products:
        product_price_map = {}
        try:
            product_prices = stripe.Price.list(product=product.id, currency=currency, active=True)
        # if the currency is invalid, return a 400
        except stripe.error.InvalidRequestError:
            raise BadRequest("(Likely) Invalid currency.")
        # no prices for this product in this currency, return a 400
        if len(product_prices) == 0:
            raise BadRequest("No prices for this currency, try picking a supported one.")
        for price in product_prices.auto_paging_iter():
            product_price_map[price.recurring.interval] = {
                "formatted_price": format_currency(price.unit_amount / 100, currency.upper()),
                "price_id": price.id
            }

        # parse the feature list from the metadata
        features = product.metadata.get("features", "").split(";")

        # add the prices to the prices dict
        prices.append({"name": product.name, "prices": product_price_map, "features": features})

    return render_template(
        "premium.html",
        currencies=["USD", "EUR", "GBP", "CAD"],
        active_currency=currency.upper(),
        user=f"{user.username}#{user.discriminator}",
        stripe_subscription_id=user_db.stripe_subscription_id,
        prices=prices,
        pending_free_trial=user_db.free_trial_pending,
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
        raise BadRequest("You must have a subscription to access the billing portal.")
    portal_session = stripe.billing_portal.Session.create(
        customer=user_db.stripe_customer_id,
        return_url=f"{config.SITE_URL}/premium",
    )
    return redirect(portal_session.url, 303)


@app.route("/premium/checkout", methods=["POST"])
@requires_authorization
def premium_checkout():
    user = discord.fetch_user()

    # fetch the price ID from the form
    price_id = request.form["price_id"]

    # try to fetch the user from the DB
    user_db = User.query.filter_by(discord_id=user.id).first()
    # if it exists, check for a stripe customer ID
    if user_db is not None and user_db.stripe_customer_id is not None:
        # skip filling in details and immediately redirect to Stripe
        return redirect(url_for("premium_checkout_redirect", price_id=price_id), 303)
    elif user_db is None:
        # create the user in the DB
        user_db = User(discord_id=user.id)
        db.session.add(user_db)
        db.session.commit()

    price = stripe.Price.retrieve(
        price_id,
        expand=["product"],
    )

    tier = price.product.metadata.get("tier")
    try:
        tier = int(tier)
    except ValueError:
        raise BadRequest("Invalid tier.")
    wants_free_trial = user_db.free_trial_pending
    free_trial_eligible = tier == 1 and wants_free_trial

    tier_name = price.product.name
    # format the price nicely
    price_fmt = format_currency(price.unit_amount / 100, price.currency.upper())  # why is the currency case-sensitive?
    period = price.recurring.interval

    return render_template(
        "premium_checkout.html",
        user=f"{user.username}#{user.discriminator}",
        tier_name=tier_name,
        price=price_fmt,
        period=period,
        price_id=price_id,
        countries=COUNTRY_LIST,
        wants_free_trial=wants_free_trial,
        free_trial_eligible=free_trial_eligible,
    )


@app.route("/premium/checkout/redirect", methods=["POST", "GET"])
@requires_authorization
def premium_checkout_redirect():
    user = discord.fetch_user()
    user_email = user.email

    price_id = request.args.get("price_id") if request.method == "GET" else request.form["price_id"]

    # try fetching the user from the DB
    user_db = User.query.filter_by(discord_id=user.id).first()
    if user_db is None or user_db.stripe_customer_id is None:
        if request.method == "GET":
            raise MethodNotAllowed("GET")

        # the incoming form has all these fields
        try:
            full_name = request.form["full_name"]
            address_line_1 = request.form["address_line_1"]
            address_line_2 = request.form["address_line_2"]
            city = request.form["city"]
            province = request.form["province"]
            postal_code = request.form["postal_code"]
            country = request.form["country"]
        except KeyError:
            raise BadRequest("Missing form data.")

        # validate the data
        if len(country) != 2:  # expect a 2-letter country code
            raise BadRequest("Invalid country code, it should be ISO 3166-1 alpha-2 format.")
        # check all the fields are filled in
        if not all([full_name, address_line_1, city, province, postal_code, country]):
            raise BadRequest("Missing form data.")

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
            metadata={
                "discord_id": user.id,
            }
        )

        # update the existing user in the DB or create a new one if it doesn't exist
        if user_db is None:
            user_db = User(discord_id=user.id, stripe_customer_id=customer.id)
            db.session.add(user_db)
        else:
            user_db.stripe_customer_id = customer.id
        db.session.commit()

    subscription_data = {}
    if user_db.free_trial_pending:
        # remove the free trial pending flag
        user_db.free_trial_pending = False
        db.session.commit()

        # add it to the session
        subscription_data["trial_period_days"] = 3
        subscription_data["trial_settings"] = {
            "end_behavior": {
                "missing_payment_method": "cancel"
            },
        }

    # create a checkout session
    checkout_session = stripe.checkout.Session.create(
        line_items=[
            {
                "price": price_id,
                "quantity": 1,
            },
        ],
        automatic_tax={
            'enabled': True,
        },
        mode="subscription",
        allow_promotion_codes=True,
        success_url=config.SITE_URL + "/premium/success?session_id={CHECKOUT_SESSION_ID}",
        cancel_url=config.SITE_URL + "/premium",
        customer=user_db.stripe_customer_id,
        subscription_data=subscription_data,
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


@app.route("/premium/create_free_trial", methods=["POST"])
@requires_authorization
def premium_create_free_trial():
    # check if the authenticated user has admin permissions
    user = discord.fetch_user()
    discord_id = user.id
    if discord_id not in config.ADMIN_IDS:
        raise Forbidden("You are not an admin.")

    target_id = request.form["discord_id"]
    # TODO: make API call to bot to check if the user has already been given a free trial

    user_id = User.query.filter_by(discord_id=target_id).first()
    if user_id is None:
        user_id = User(discord_id=target_id, free_trial_pending=True)
        db.session.add(user_id)
    else:
        user_id.free_trial_pending = True
    db.session.commit()
    return redirect("/admin/dashboard", 303)


@app.route('/stripe_webhook', methods=['POST'])
def webhook_received():
    # Retrieve the event by verifying the signature using the raw body and secret
    signature = request.headers.get('stripe-signature')
    try:
        root_event = stripe.Webhook.construct_event(
            payload=request.data, sig_header=signature, secret=config.STRIPE_WEBHOOK_SECRET)
        print(root_event)
        data = root_event['data']
    except Exception as e:
        return e
    # Get the type of webhook event sent - used to check the status of PaymentIntents.
    event_type = root_event['type']
    data_object = data['object']
    data_previous = data.get('previous_attributes', {})
    is_live = root_event["livemode"]

    print('event ' + event_type)

    json_model = None

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
        json_model = {
            "user_id": discord_id,
            "live_mode": is_live,
            "event": {
                "t": "customer.subscription.trial_will_end",
                "d": {
                    "trial_end": data_object["trial_end"]
                }
            }
        }

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
                discord_id = config.DEBUG_FALLBACK_ID
            else:
                return jsonify({'status': 'success'})
        else:
            # Update the user in the DB
            user_db.subscribed = True
            user_db.stripe_subscription_id = data_object["items"]["data"][0]["id"]
            db.session.commit()
            discord_id = user_db.discord_id

        # if the subscription is not active, we don't care about it yet
        if data_object["status"] != "active":
            return jsonify({'status': 'success'})

        # To grab the metadata, we need to grab the plan's product ID, then grab the metadata from that
        product_id = data_object["plan"]["product"]
        product = stripe.Product.retrieve(product_id)
        tier = int(product["metadata"]["tier"])

        # Prepare the event object
        json_model = {
            "user_id": discord_id,
            "live_mode": is_live,
            "event": {
                "t": "customer.subscription.created",
                "c": {
                    "tier": tier
                }
            }
        }

    elif event_type == 'customer.subscription.updated':
        print('Subscription created', root_event.id)
        print("Product ID", data_object['plan']['product'])
        print("Customer ID", data_object['customer'])
        print("Status", data_object["status"])

        # if data["previous_attributes"] contains only *exactly* current_period_start, current_period_end,
        # and latest_invoice, then the subscription was renewed
        keys = ["current_period_start", "current_period_end", "latest_invoice"]
        is_renewed = len(data_previous) == len(keys) and all(
            key in data_previous for key in keys)

        # if data["previous_attributes"]["plan"]["interval"] is not equal to data["plan"]["interval"], then
        # the subscription has changed length
        current_interval = data_object["plan"]["interval"]
        try:
            is_length_change = data_previous["plan"]["interval"] != current_interval
        except KeyError:
            is_length_change = False

        # if data["previous_attributes"]["status"] was not "active" or "trialing," and data["status"] is "active," then
        # the subscription has succeeded
        currently_active = data_object["status"] == "active"
        try:
            is_new = data_previous["status"] not in ["active", "trialing"] and currently_active
        except KeyError:
            is_new = False

        # if the previous plan's product ID is not equal to the current plan's product ID, then the subscription
        # has changed tiers
        current_tid = data_object["plan"]["product"]
        try:
            is_tier_change = data_previous["plan"]["product"] != current_tid
        except KeyError:
            is_tier_change = False

        # Get the user from the DB
        # If we're not in live mode, fake a user ID of 0 if none exists
        user_db = User.query.filter_by(stripe_customer_id=data_object['customer']).first()
        if user_db is None:
            if not is_live:
                if is_renewed:
                    print("subscription was renewed")
                discord_id = config.DEBUG_FALLBACK_ID
            else:
                # try falling back to metadata
                try:
                    discord_id = int(data_object["metadata"]["discord_id"])
                except KeyError:
                    # no metadata, so we can't do anything
                    return jsonify({'status': 'success'})
        else:
            discord_id = user_db.discord_id

        # To grab the metadata, we need to grab the plan's product ID, then grab the metadata from that
        product_id = data_object["plan"]["product"]
        product = stripe.Product.retrieve(product_id)
        try:
            tier = int(product["metadata"]["tier"])
        except KeyError:
            # not a tiered product
            return jsonify({'status': 'success'})

        # Prepare the event object
        json_model = {
            "user_id": discord_id,
            "live_mode": is_live,
            "event": {
                "t": "customer.subscription.updated",
                "c": {
                    "tier": tier,
                    "status": data_object["status"],
                    "cancel_at_period_end": data_object["cancel_at_period_end"],
                    "current_period_start": data_object["current_period_start"],
                    "current_period_end": data_object["current_period_end"],
                    "trial_end": data_object["trial_end"],
                    "is_renewal": is_renewed,
                    "is_length_change": is_length_change,
                    "is_new": is_new,
                    "is_tier_change": is_tier_change
                }
            }
        }

    elif event_type == 'customer.subscription.deleted':
        print('Subscription canceled', root_event.id)
        print("Product ID", data_object['plan']['product'])
        print("Customer ID", data_object['customer'])
        print("Ends at", data_object["cancel_at"])
        print("Status", data_object["status"])

        # Get the user from the DB
        # If we're not in live mode, fake a user ID of 0 if none exists
        user_db = User.query.filter_by(stripe_customer_id=data_object['customer']).first()
        if user_db is None:
            if not is_live:
                discord_id = config.DEBUG_FALLBACK_ID
            else:
                return jsonify({'status': 'success'})
        else:
            # Delete the user's subscription ID from the DB
            user_db.stripe_subscription_id = None
            db.session.commit()
            discord_id = user_db.discord_id

        # To grab the metadata, we need to grab the plan's product ID, then grab the metadata from that
        product_id = data_object["plan"]["product"]
        product = stripe.Product.retrieve(product_id)
        try:
            tier = int(product["metadata"]["tier"])
        except KeyError:
            # not a tiered product
            return jsonify({'status': 'success'})

        # Prepare the event object
        json_model = {
            "user_id": discord_id,
            "live_mode": is_live,
            "event": {
                "t": "customer.subscription.deleted",
                "c": {
                    "tier": tier,
                }
            }
        }

    elif event_type == "radar.early_fraud_warning":
        print('Early fraud warning', root_event.id)
        print("Charge ID", data_object['charge'])
        print("Reason", data_object["fraud_type"])
        if data_object["actionable"]:
            # reverse the charge and fire the cancelled subscription event
            charge = stripe.Charge.retrieve(data_object['charge'], expand=["customer", "customer.subscriptions"])
            stripe.Refund.create(charge=charge.id)
            print("Charge reversed")
            if (subscription := charge.customer.subscriptions.data.get(0)) is not None:
                stripe.Subscription.delete(subscription.id)
                print("Subscription cancelled")
                # delete the subscription ID from the DB too
                user_db = User.query.filter_by(stripe_customer_id=charge.customer.id).first()
                if user_db is not None:
                    user_db.stripe_subscription_id = None
                    db.session.commit()
                # no event to fire here, as Stripe will fire subscription.deleted

    elif event_type == "customer.source.expiring":
        print('Card expiring', root_event.id)
        print("Customer ID", data_object['customer'])

        # Get the user from the DB
        # If we're not in live mode, fake a user ID of 0 if none exists
        user_db = User.query.filter_by(stripe_customer_id=data_object['customer']).first()
        if user_db is None:
            if not is_live:
                discord_id = config.DEBUG_FALLBACK_ID
            else:
                return jsonify({'status': 'success'})
        else:
            discord_id = user_db.discord_id

        # Prepare the event object
        json_model = {
            "user_id": discord_id,
            "live_mode": is_live,
            "event": {
                "t": "customer.source.expiring",
                "d": {
                    "brand": data_object["source"]["brand"],
                    "last4": data_object["source"]["last4"],
                }
            }
        }

    elif event_type == "charge.dispute.created":
        print('Dispute created', root_event.id)
        print("Charge ID", data_object['charge'])

        # We don't have a customer ID here, so we can't get the user from the DB
        # fetch the charge and get the user ID from the metadata
        charge = stripe.Charge.retrieve(data_object['charge'])
        stripe_customer_id = charge.customer
        if stripe_customer_id is None:
            print("Got a dispute for a charge with no customer ID")
            return jsonify({'status': 'success'})
        user_db = User.query.filter_by(stripe_customer_id=stripe_customer_id).first()
        if user_db is None:
            if not is_live:
                discord_id = config.DEBUG_FALLBACK_ID
            else:
                return jsonify({'status': 'success'})
        else:
            discord_id = user_db.discord_id

        # Prepare the event object
        json_model = {
            "user_id": discord_id,
            "live_mode": is_live,
            "event": {
                "t": "charge.dispute.created",
                "d": {}  # no data to send here since we don't need it
            }
        }

    else:
        # no need to handle this event
        pass

    if json_model is not None:
        print("Firing bot notification")
        print(json_model)
        resp = session.post(
            f"{config.BOT_API_URL}/premium/stripe_webhook",
            json=json_model,
            headers={"Authorization": config.BOT_API_TOKEN}
        )
        print(resp.status_code)
        # if not successful, log the error
        if resp.status_code != 200:
            print(resp.text)
    else:
        print("No webhook fired")

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
        raise BadRequest("No country found")
    try:
        return jsonify(PROVINCE_LIST[country])
    except KeyError:
        raise BadRequest("Invalid country")


@app.errorhandler(flask_discord.Unauthorized)
def handle_unauthorized(_):
    return redirect(url_for("oauth_redirect"))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=3000)
