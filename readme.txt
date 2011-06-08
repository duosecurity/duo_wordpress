=== Duo Two-Factor Authentication ===
Contributors: duosecurity
Tags: authentication, two-factor, login, username, password, duo, security
Requires at least: 2.8
Tested up to: 3.1.2
Stable tag: 1.3

This plugin enables Duo Security's two-factor authentication for WordPress logins.

== Description ==

This plugin enables Duo Security's two-factor authentication for WordPress logins.

Duo provides simple two-factor authentication as a service via:

* Phone callback
* SMS-delivered one-time passcodes
* Duo mobile app to generate one-time passcodes
* Duo mobile app for smartphone push authentication
* Duo hardware token to generate one-time passcodes

This plugins allows a WordPress administrator to quickly add strong two-factor authentication to any WordPress instance without setting up user accounts, directory synchronization, servers, or hardware.

== Installation ==

Integrating Duo two-factor authentication with WordPress is a breeze. Follow these quick installation steps and you'll be up and running in no time:

1. Sign up for a free account at [http://www.duosecurity.com](http://www.duosecurity.com).

2. After signing up and activating your account, add a "Web SDK" integration in the Duo administrative interface and set its "Visual Style" to "WordPress".

3. Install and activate the Duo WordPress plugin.

4. In the plugin settings, fill in the "Integration Key" and "Secret Key" that corresponds to the integration you added in the Duo administrative interface. Also, check the user roles that you'd like to require Duo login.

5. Log out of your WordPress. Upon logging back in, you'll be prompted to enroll and authenticate using Duo's two-factor service.

== Frequently Asked Questions ==

= How do I get started with Duo? =

Before installing the plugin, you'll need to sign up for a free account at [http://www.duosecurity.com](http://www.duosecurity.com).

= Is Duo's two-factor service really free? =

Yes, Duo is free up to 10 users and no credit card is required to get started! If you go beyond 10 users, it's only $3/user/month.

= WordPress integration is great, but what if I want to protect my own web applications with two-factor? =

If you're interested in protecting other web applications with Duo's two-factor authentication, check out our [web SDK](https://github.com/duosecurity/duo_web/) that allows for easy integration with any web application.

== Screenshots ==

1. Duo's WordPress integration adds strong two-factor authentication to any WordPress login. After entering their primary credentials (a username and password), the user is challenged to complete secondary authentication via Duo Push, phone callback, or one-time passcodes generated via the Duo Mobile app or delivered via SMS.

2. The Duo Mobile application allows users to generate passcodes or use Duo Push to perform secondary authentication using their mobile device.

== Changelog ==

= 1.3 =
* Default all roles to enable Duo login for upgraded users (same as new installs).
* Require the API hostname setting
* Code cleanups

= 1.2 =
* Select which roles need to authenticate with Duo

= 1.1.1 =
* CSS fixes for IE 6, 7, and 8

= 1.1 =
* Minor tweaks

= 1.0 =
* Initial release!

== Upgrade Notice ==

= 1.3 =
* Default all roles to enable Duo login for upgraded users (same as new installs).
* Require the API hostname setting
* Code cleanups

= 1.2 =
* Select which roles need to authenticate with Duo

= 1.1.1 =
* CSS fixes for IE 6, 7, and 8

= 1.1 =
* Minor tweaks

= 1.0 =
* Initial release!
