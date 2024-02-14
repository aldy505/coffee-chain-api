# Requirements

This document specifies requirements for the Coffee Chain API.

## What the customers can do

* User can register via email and password. 
  * No TOTP 2FA because I'm lazy.
  * No password strength checker.
* User can login with email and password.
* User can logout, obviously.
* User can edit their profile data, that consist of:
  * Name
  * Gender (Male, Female, Others)
  * Notification settings (promotional, transactional)
* User can see list of stores
* User can browse products
* User can see ongoing promotion
* User can receive push notifications for promotional or transactional
* User can execute a pick-up order (order now, pick up later). No delivery order.
* User can acquire points by spending/purchase, with rules as such:
  * 1 point is acquired for every purchase of IDR 1000
  * If there is a promotion that reduce the purchase amount, it will accumulate to the final projected amount
* User can redeem points to free product based on agreed terms and conditions
* User can redeem promotion voucher for in-store transaction.

## What the merchant cashier can do

* User can input product items to create an order
* User can move current order state, with the states defined as such:
  * Accepted
  * On Process
  * Ready for pickup
* User can update the availability of a certain product item
* User can update the operational state of their store (open or closed)

## What the management can do

* User can register a merchant account and assign to a specific store
* User can create new store (physical store)
* User can create new product
  * Base product (+ price)
  * Variant / sides (sugar, extra espresso, ice) (+ price)
  * Maximum product order quantity per person
* User can modify product, obviously

No analytics yet, maybe we won't have much time.