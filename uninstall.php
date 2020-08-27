<?php

defined('ABSPATH') or die('Direct Access Denied');
//if uninstall not called from WordPress exit
if ( !defined( 'WP_UNINSTALL_PLUGIN' ) )
        exit ();
//Delete Duo credentials in wp_options
delete_option('duo_ikey');
delete_option('duo_skey');
delete_option('duo_host');
delete_option('duo_roles');
delete_option('duo_xmlrpc');

//Delete Duo credentials in wp_sitemeta
delete_site_option('duo_ikey');
delete_site_option('duo_skey');
delete_site_option('duo_host');
delete_site_option('duo_roles');
delete_site_option('duo_xmlrpc');

?>
