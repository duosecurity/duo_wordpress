<?php
/*
Plugin Name: Duo Two-Factor Authentication
Plugin URI: http://wordpress.org/extend/plugins/duo-wordpress/
Description: This plugin enables Duo two-factor authentication for WordPress logins.
Version: 1.5
Author: Duo Security
Author URI: http://www.duosecurity.com
License: GPL2
*/

/*
Copyright 2011 Duo Security <duo_web@duosecurity.com>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License, version 2, as 
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

    require_once("duo_web/duo_web.php");

    function duo_sign_request($user, $redirect) {
        $ikey = duo_get_option('duo_ikey');
        $skey = duo_get_option('duo_skey');
        $host = duo_get_option('duo_host');
       
        $username = $user->user_login;

        $request_sig = Duo::signRequest($ikey, $skey, $username);

        $exptime = duo_get_time() + 3600; // let the duo login form expire within 1 hour
?>
    <html>
        <head>
            <?php
                global $wp_version;
                if(version_compare($wp_version, "3.3", "<=")){
            ?>
                    <link rel="stylesheet" type="text/css" href="<?php echo admin_url('css/login.css'); ?>" />
            <?php
                }
                else{
            ?>
                    <link rel="stylesheet" type="text/css" href="<?php echo admin_url('css/wp-admin.css'); ?>" />
                    <link rel="stylesheet" type="text/css" href="<?php echo admin_url('css/colors-fresh.css'); ?>" />
            <?php
                }
            ?>

            <style>
                body {
                    background:#F9F9F9;
                }
                div {
                    background: transparent;
                }
            </style>
        </head>

        <body class="login" >
            <script src="<?php echo plugins_url('duo_web/Duo-Web-v1.bundled.min.js', __FILE__); ?>"></script>
            <script>
            Duo.init({
                'host': <?php echo "'" . $host . "'"; ?>,
                'post_action': '<?php echo wp_login_url() ?>',
                'sig_request':<?php echo "'" . $request_sig . "'"; ?>
            });
            </script>

            <div style="width: 100%; text-align: center;">
                <div style="width:500px; text-align: left;" id="login">
                    <h1 style="text-align:center;"><a style="width: 500px;" href="http://wordpress.org/" title="Powered by WordPress"><?php echo get_bloginfo('name'); ?></a></h1>
                    <div style="text-align: center;">
                        <iframe id="duo_iframe" width="500" height="900" frameborder="0" allowtransparency="true" style="background: transparent;"></iframe>
                    </div>
                    <form method="POST" style="display:none;" id="duo_form">
                        <input type="hidden" name="redirect_to" value="<?php echo esc_attr($redirect); ?>"/>
                        <input type="hidden" name="u" value="<?php echo esc_attr($username); ?>"/>
                        <input type="hidden" name="exptime" value="<?php echo esc_attr($exptime); ?>"/>
                        <input type="hidden" name="uhash" value="<?php echo esc_attr(wp_hash($username.$exptime)); ?>"/>
                    </form>
                </div>
            </div>
        </body>
    </html>
<?php
    }
    
    function duo_authenticate_user($user="", $username="", $password="") {
        // play nicely with other plugins if they have higher priority than us
        if (is_a($user, 'WP_User')) {
            return $user;
        }

        if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) 
            return; //allows the XML-RPC protocol for remote publishing

        if (duo_get_option("duo_ikey", "") == "" || duo_get_option("duo_skey", "") == "" || duo_get_option("duo_host", "") == "") {
            return;
        }

        if (isset($_POST['sig_response'])) {
            // secondary auth
            remove_action('authenticate', 'wp_authenticate_username_password', 20);

            $sig = wp_hash($_POST['u'] . $_POST['exptime']);
            $expire = intval($_POST['exptime']);

            if (wp_hash($_POST['uhash']) == wp_hash($sig) && duo_get_time() < $expire) {
                $user = get_user_by('login', $_POST['u']);

                if ($user->user_login == Duo::verifyResponse(duo_get_option('duo_skey'), $_POST['sig_response'])) {
                    return $user;
                }
            } else {
                $user = new WP_Error('Duo authentication_failed', __('<strong>ERROR</strong>: Failed or expired two factor authentication'));
                return $user;
            }
        }

        if (strlen($username) > 0) {
            // primary auth
            $user = get_user_by('login', $username);
            if (!$user) {
                return;
            }

            global $wp_roles;
            foreach ($wp_roles->get_names() as $k=>$r) {
                $all_roles[$k] = $r;
            }

            $duo_roles = duo_get_option('duo_roles', $all_roles); 
            $duo_auth = false;

            /*
             * Mainly a workaround for multisite login:
             * if a user logs in to a site different from the one 
             * they are a member of, login will work however
             * it appears as if the user has no roles during authentication
             * "fail closed" in this case and require duo auth
             */
            if(empty($user->roles)) {
                $duo_auth = true;
            }

            if (!empty($user->roles) && is_array($user->roles)) {
                foreach ($user->roles as $role) {
                    if (array_key_exists($role, $duo_roles)) {
                        $duo_auth = true;
                    }
                }
            }

            if (!$duo_auth) {
                return;
            }

            remove_action('authenticate', 'wp_authenticate_username_password', 20);
            $user = wp_authenticate_username_password(NULL, $username, $password);
            if (!is_a($user, 'WP_User')) {
                // on error, return said error (and skip the remaining plugin chain)
                return $user;
            } else {
                duo_sign_request($user, $_POST['redirect_to']);
                exit();
            }
        }
    }

    function duo_settings_page() {
?>
    <div class="wrap">
        <h2>Duo Two-Factor Authentication</h2>
        <?php if(is_multisite()) { ?>
            <form action="ms-options.php" method="post">
        <?php } else { ?>
            <form action="options.php" method="post"> 
        <?php } ?>
            <?php settings_fields('duo_settings'); ?>
            <?php do_settings_sections('duo_settings'); ?> 
            <p class="submit">
                <input name="Submit" type="submit" value="<?php esc_attr_e('Save Changes'); ?>" />
            </p>
        </form>
    </div>
<?php
    }

    function duo_settings_ikey() {
        $ikey = esc_attr(duo_get_option('duo_ikey'));
        echo "<input id='duo_ikey' name='duo_ikey' size='40' type='text' value='$ikey' />";
    }

    function duo_settings_skey() {
        $skey = esc_attr(duo_get_option('duo_skey'));
        echo "<input id='duo_skey' name='duo_skey' size='40' type='text' value='$skey' />";
    }

    function duo_settings_host() {
        $host = esc_attr(duo_get_option('duo_host'));
        echo "<input id='duo_host' name='duo_host' size='40' type='text' value='$host' />";
    }

    function duo_settings_roles() {
        global $wp_roles;

        $roles = $wp_roles->get_names();
        $newroles = array();
        foreach($roles as $key=>$role) {
            $newroles[before_last_bar($key)] = before_last_bar($role);
        }

        $selected = duo_get_option('duo_roles', $newroles);

        foreach ($wp_roles->get_names() as $key=>$role) {
            //create checkbox for each role
?>
            <input id="duo_roles" name='duo_roles[<?php echo $key; ?>]' type='checkbox' value='<?php echo $role; ?>'  <?php if(in_array($role, $selected)) echo 'checked="checked"'; ?> /> <?php echo $role; ?> <br />
<?php
        }


    }

    function duo_roles_validate($options) {
        //return empty array
        if (!is_array($options) || empty($options) || (false === $options)) {
            return array();
        }

        global $wp_roles;
        $valid_roles = $wp_roles->get_names();
        //otherwise validate each role and then return the array
        foreach ($options as $opt) {
            if (!in_array($opt, $valid_roles)) {
                unset($options[$opt]);
            }
        }
        return $options;
    }

    function duo_settings_text() {
        echo "<p>If you don't yet have a Duo account, sign up now for free at <a target='_blank' href='http://www.duosecurity.com'>http://www.duosecurity.com</a>.</p>";
        echo "<p>To enable Duo two-factor authentication for your WordPress login, you need to configure your integration settings.</p>";
        echo "<p>You can retrieve your integration key, secret key, and API hostname by logging in to the Duo administrative interface.</p>";
    }

    function duo_ikey_validate($ikey) {
        if (strlen($ikey) != 20) {
            add_settings_error('duo_ikey', '', 'Integration key is not valid');
            return "";
        } else {
            return $ikey;
        }
    }
    
    function duo_skey_validate($skey){
        if (strlen($skey) != 40) {
            add_settings_error('duo_skey', '', 'Secret key is not valid');
            return "";
        } else {
            return $skey;
        }
    }

    function duo_settings_xmlrpc() {
        $val = '';
        if(duo_get_option('duo_xmlrpc', 'off') == 'off') {
            $val = "checked='checked'";
        }
        echo "<input id='duo_xmlrpc' name='duo_xmlrpc' type='checkbox' value='off' $val /> Yes<br />";
        echo "Using XML-RPC bypasses two-factor authentication and makes your website less secure. We recommend only using the WordPress web interface for managing your WordPress website.";
    }

    function duo_xmlrpc_validate($option) {
        if($option == 'off') {
            return $option;
        }
        return 'on';
    }

    function duo_admin_init() {
        if (is_multisite()) {
            global $wp_roles;
            $roles = $wp_roles->get_names();
            $allroles = array();
            foreach($roles as $key=>$role) {
                $allroles[before_last_bar($key)] = before_last_bar($role);
            }

            add_site_option('duo_ikey', '');
            add_site_option('duo_skey', '');
            add_site_option('duo_host', '');
            add_site_option('duo_roles', $allroles);
            add_site_option('duo_xmlrpc', 'off');
        }
        else {
            add_settings_section('duo_settings', 'Main Settings', 'duo_settings_text', 'duo_settings');
            add_settings_field('duo_ikey', 'Integration key', 'duo_settings_ikey', 'duo_settings', 'duo_settings');
            add_settings_field('duo_skey', 'Secret key', 'duo_settings_skey', 'duo_settings', 'duo_settings');
            add_settings_field('duo_host', 'API hostname', 'duo_settings_host', 'duo_settings', 'duo_settings');
            add_settings_field('duo_roles', 'Enable for roles:', 'duo_settings_roles', 'duo_settings', 'duo_settings');
            add_settings_field('duo_xmlrpc', 'Disable XML-RPC (recommended)', 'duo_settings_xmlrpc', 'duo_settings', 'duo_settings');
            register_setting('duo_settings', 'duo_ikey', 'duo_ikey_validate');
            register_setting('duo_settings', 'duo_skey', 'duo_skey_validate');
            register_setting('duo_settings', 'duo_host');
            register_setting('duo_settings', 'duo_roles', 'duo_roles_validate');
            register_setting('duo_settings', 'duo_xmlrpc', 'duo_xmlrpc_validate');
        }

    }

    function duo_mu_options() {

?>
        <h3>Duo Security</h3>
        <table class="form-table">
            <?php duo_settings_text();?></td></tr>
            <tr><th>Integration key</th><td><?php duo_settings_ikey();?></td></tr>
            <tr><th>Secret key</th><td><?php duo_settings_skey();?></td></tr>
            <tr><th>API hostname</th><td><?php duo_settings_host();?></td></tr>
            <tr><th>Roles</th><td><?php duo_settings_roles();?></td></tr>
            <tr><th>Disable XML-RPC</th><td><?php duo_settings_xmlrpc();?></td></tr>
        </table>
<?php
    }

    function duo_update_mu_options() {
        if(isset($_POST['duo_ikey'])) {
            $ikey = $_POST['duo_ikey'];
            $result = update_site_option('duo_ikey', $ikey);
        }

        if(isset($_POST['duo_skey'])) {
            $skey = $_POST['duo_skey'];
            $result = update_site_option('duo_skey', $skey);
        }

        if(isset($_POST['duo_host'])) {
            $host = $_POST['duo_host'];
            $result = update_site_option('duo_host', $host);
        }

        if(isset($_POST['duo_roles'])) {
            $roles = $_POST['duo_roles'];
            $result = update_site_option('duo_roles', $roles);
        }

        if(isset($_POST['duo_xmlrpc'])) {
            $xmlrpc = $_POST['duo_xmlrpc'];
            $result = update_site_option('duo_xmlrpc', $roles);
        }
    }

    function duo_add_page() {
        if(! is_multisite()) {
            add_options_page('Duo Two-Factor', 'Duo Two-Factor', 'manage_options', 'duo_wordpress', 'duo_settings_page');
        }
    }

    function duo_add_link($links, $file) {
        static $this_plugin;
        if (!$this_plugin) $this_plugin = plugin_basename(__FILE__);

        if ($file == $this_plugin) {
            $settings_link = '<a href="options-general.php?page=duo_wordpress">'.__("Settings", "duo_wordpress").'</a>';
            array_unshift($links, $settings_link);
        }
        return $links;
    }

    /* Get Duo's system time.
     * If that fails then use server system time
     */
    function duo_get_time() {
        $duo_url = 'https://' . duo_get_option('duo_host') . '/auth/v2/ping';
        $response = json_decode(file_get_contents($duo_url), true);
        $time = (int)$response['response']['time'];
        $time = ($time != NULL ? $time : time());
        return $time;
    }

    /*-------------XML-RPC Features-----------------*/
    
    if(duo_get_option('duo_xmlrpc', 'off') == 'off') {
        add_filter( 'xmlrpc_enabled', '__return_false' );
    }

    /*-------------Register WordPress Hooks-------------*/

    add_filter('authenticate', 'duo_authenticate_user', 10, 3);
    add_filter('plugin_action_links', 'duo_add_link', 10, 2 );
    if(is_multisite() && is_network_admin()){
        add_action('network_admin_menu', 'duo_add_page');
        
        // Custom fields in network settings
        add_filter('wpmu_options', 'duo_mu_options');
        add_filter('update_wpmu_options', 'duo_update_mu_options');
    }
    else {
        add_action('admin_menu', 'duo_add_page');
    }
    add_action('admin_init', 'duo_admin_init');

    function duo_get_option($key, $default="") {
        if (is_multisite()) {
            return get_site_option($key, $default);
        }
        else {
            return get_option($key, $default);
        }
    }

?>
