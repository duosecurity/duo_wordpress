<?php

defined('ABSPATH') or die('Direct Access Denied');
//if uninstall not called from WordPress exit
if ( !defined( 'WP_UNINSTALL_PLUGIN' ) )
        exit ();
//if there are Duo credentials in wp_options, then delete all Duo credentials
if (get_option('duo_ikey')) {
    delete_option('duo_ikey');
    delete_option('duo_skey');
    delete_option('duo_host');
    delete_option('duo_roles');
    delete_option('duo_xmlrpc');
}

//if there are Duo credentials in wp_sitemeta, then delete all Duo credentials
if (get_site_option('duo_ikey')) {
    delete_site_option('duo_ikey');
    delete_site_option('duo_skey');
    delete_site_option('duo_host');
    delete_site_option('duo_roles');
    delete_site_option('duo_xmlrpc');
}

?>
