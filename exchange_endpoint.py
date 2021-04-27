from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import math
import sys
import traceback

from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

from models import Base, Order, TX
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

""" Pre-defined methods (do not need to change) """

@app.before_request
def create_session():
    g.session = scoped_session(DBSession)

@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()

def connect_to_blockchains():
    try:
        # If g.acl has not been defined yet, then trying to query it fails
        acl_flag = False
        g.acl
    except AttributeError as ae:
        acl_flag = True
    
    try:
        if acl_flag or not g.acl.status():
            # Define Algorand client for the application
            g.acl = connect_to_algo()
    except Exception as e:
        print("Trying to connect to algorand client again")
        print(traceback.format_exc())
        g.acl = connect_to_algo()
    
    try:
        icl_flag = False
        g.icl
    except AttributeError as ae:
        icl_flag = True
    
    try:
        if icl_flag or not g.icl.health():
            # Define the index client
            g.icl = connect_to_algo(connection_type='indexer')
    except Exception as e:
        print("Trying to connect to algorand indexer client again")
        print(traceback.format_exc())
        g.icl = connect_to_algo(connection_type='indexer')

        
    try:
        w3_flag = False
        g.w3
    except AttributeError as ae:
        w3_flag = True
    
    try:
        if w3_flag or not g.w3.isConnected():
            g.w3 = connect_to_eth()
    except Exception as e:
        print("Trying to connect to web3 again")
        print(traceback.format_exc())
        g.w3 = connect_to_eth()
        
""" End of pre-defined methods """
        
""" Helper Methods (skeleton code for you to implement) """

def log_message(message):
    #msg = json.dumps(message_dict)

    # TODO: Add message to the Log table
    time = datetime.now()
    log = Log(logtime=time, message=message)
    g.session.add(log)
    g.session.commit()
    pass
    
    return

def get_algo_keys():
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the algorand public/private keys
    mnemonic_secret = "polar taxi broccoli decrease ten decrease illness engine suit useless unit planet eternal abandon click during adapt decide jazz proud evil kingdom century abstract empty"
    sk = mnemonic.to_private_key(mnemonic_secret)
    pk = mnemonic.to_public_key(mnemonic_secret)
        
    return algo_sk, algo_pk

def get_eth_keys(filename = "eth_mnemonic.txt"):
    w3 = Web3()
    f = open(filename,"r")
    if error:
        w3.eth.account.enable_unaudited_hdwallet_features()
        acct,mnemonic_secret = w3.eth.account.create_with_mnemonic()
        f = open(filename, "w")
        f.write(mnemonic_secret)
    mnemonic_secret = f.read()
    acct = w3.eth.account.from_mnemonic(mnemonic_secret)
    eth_pk = acct._address
    eth_sk = acct._private_key
    return eth_sk, eth_pk

def check_sig(payload,sig):
    s_pk = payload['sender_pk'] 
    platform = payload['platform']
    response = False
    if platform=='Ethereum':
        eth_encoded_msg = eth_account.messages.encode_defunct(text=json.dumps(payload))
        if eth_account.Account.recover_message(eth_encoded_msg,signature=sig) == s_pk:
            response = True
    if platform=='Algorand':
        if algosdk.util.verify_bytes(json.dumps(payload).encode('utf-8'),sig,s_pk):
            response = True
    return response

def check_match(tx, order):
    if(order.filled==None):
        if(tx.buy_currency == order.sell_currency):
            if(tx.sell_currency == order.buy_currency):
                if(tx.sell_amount / tx.buy_amount >= order.buy_amount/order.sell_amount):
                     return True
    return False

def match_order(tx, order):  
    if (tx.sell_amount < order.buy_amount):
        remaining_buy_amt = order.buy_amount - tx.sell_amount
        remaining_sell_amt = order.sell_amount - tx.buy_amount
        derived_order = Order (
            creator_id=order.id, 
            sender_pk=order.sender_pk,
            receiver_pk=order.receiver_pk, 
            buy_currency=order.buy_currency, 
            sell_currency=order.sell_currency, 
            buy_amount=remaining_buy_amt, 
            sell_amount= remaining_sell_amt)
        derived_order.timestamp = datetime.now()
        derived_order.relationship = (derived_order.id, order.id)
        g.session.add(derived_order)
        g.session.commit()
        tx.filled = order.timestamp 
        order.filled = order.timestamp
        tx.counterparty_id = order.id
        order.counterparty_id = tx.id
    return 0

def fill_order(order, txes=[]):
    # TODO: 
    # Match orders (same as Exchange Server II)
    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
    # Make sure that you end up executing all resulting transactions!
    for tx in txes:
        if tx.filled == None:
            if(check_match(tx, order)==True):
                match_order(tx, order)
    pass

def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print( f"Trying to execute {len(txes)} transactions" )
    print( f"IDs = {[tx['order_id'] for tx in txes]}" )
    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()
    
    if not all( tx['platform'] in ["Algorand","Ethereum"] for tx in txes ):
        print( "Error: execute_txes got an invalid platform!" )
        print( tx['platform'] for tx in txes )

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand" ]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum" ]

    # TODO: 
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table

    pass

""" End of Helper methods"""
  
@app.route('/address', methods=['POST'])
def address():
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print( f"Error: no platform provided" )
            return jsonify( "Error: no platform provided" )
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print( f"Error: {content['platform']} is an invalid platform" )
            return jsonify( f"Error: invalid platform provided: {content['platform']}"  )
        
        if content['platform'] == "Ethereum":
            keys = get_eth_keys
            eth_pk=keys[1]
            return jsonify( eth_pk )
        if content['platform'] == "Algorand":
            #Your code here
            keys = get_algo_keys()
            algo_pk=keys[1]
            return jsonify( algo_pk )

@app.route('/trade', methods=['POST'])
def trade():
    print( "In trade", file=sys.stderr )
    connect_to_blockchains()
    get_keys()
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = [ "sig", "payload" ]
        error = False
        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        # Your code here
        
        # 1. Check the signature
        response = check_sig(content['payload'], content['sig'])
        
        # 2. Add the order to the table
        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)
        # 3b. Fill the order (as in Exchange Server II) if the order is valid
        # 4. Execute the transactions
        # If all goes well, return jsonify(True). else return jsonify(False)

        if response == True:   # If the signature verifies, store remaining fields in order table.
            order = Order(sender_pk=content['payload']['sender_pk'] , 
                          receiver_pk=content['payload']['receiver_pk'], 
                          buy_currency=content['payload']['buy_currency'], 
                          sell_currency=content['payload']['sell_currency'], 
                          buy_amount=content['payload']['buy_amount'], 
                          sell_amount=content['payload']['sell_amount'])
            g.session.add(order)
            g.session.commit()
            fill_order(order, g.session.query(Order).all())
            return jsonify(True)
        if response == False:   # If the signature does not verify, insert a record into log table
            leg_message(json.dumps(content['payload']))
            return jsonify(False)


        return jsonify(True)

@app.route('/order_book')
def order_book():
    orders = g.session.query(Order).all()
    list_orders = []
    for order in orders:
        o = {"sender_pk": order.sender_pk, "receiver_pk": order.receiver_pk, 
            "buy_currency": order.buy_currency, "sell_currency": order.sell_currency, 
            "buy_amount": order.buy_amount, "sell_amount": order.sell_amount, "signature": order.signature}
        list_orders.append(o)
    return jsonify(data=list_orders)

if __name__ == '__main__':
    app.run(port='5002')
