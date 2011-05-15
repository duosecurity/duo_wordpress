<?php
/*
Plugin Name: Duo Two-Factor Authentication
Plugin URI: https://github.com/duosecurity/duo_wordpress
Description: This plugin enables Duo two-factor authentication for WordPress logins.
Version: 1.0
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

    function duo_sign_request($user, $redirect, $pass) {
        $ikey = get_option('duo_integration_key');
        $skey = get_option('duo_secret_key');
       
        $username = $user->user_login;

        $request_sig = Duo::signRequest($ikey, $skey, $username);

        $exptime = time()+300; //expire in 5 minutes

        $duo_url = get_option('duo_api_host');
        if (!$duo_url) {
            $duo_url = 'api-eval.duosecurity.com';
        }
?>
    <html>
        <head>
        <link rel="stylesheet" type="text/css" href="<?php echo admin_url('css/login.css'); ?>" />
        <style>
            body{
                 background:#F9F9F9;
            }
            div{
                background: transparent;
            }
        </style>
        </head>
        <body class="login" >
        <p id="backtoblog"><a href="<?php echo get_bloginfo('wpurl');?>" title="Are you lost?">&larr; Back to <?php echo get_bloginfo('name'); ?></a></p>
        <script src="<?php echo plugins_url('duo_web/Duo-Web-v1.bundled.min.js', __FILE__); ?>"></script>
        <script>
        Duo.init({
            'host': <?php echo "'" . $duo_url . "'"; ?>,
            'post_action':'wp-login.php',
            'sig_request':<?php echo "'" . $request_sig . "'"; ?>
        });
        </script>
        <div style="width: 100%; text-align: center;">
            <div style="width:360px; text-align: left;" id="login">
                <h1 style="text-align:center;"><a style="width: 360px;" href="http://wordpress.org/" title="Powered by WordPress"><?php echo get_bloginfo('name'); ?></a></h1>
                <div style="text-align: center;">
                    <iframe id="duo_iframe" width="380" height="600" frameborder="0" allowtransparency="true" style="background: transparent;"></iframe>
                </div>
                <form method="POST" style="display:none;" id="duo_form">
                    <input type="hidden" name="redirect_to" value="<?php echo $redirect; ?>"/>
                    <input type="hidden" name="u" value="<?php echo $username; ?>"/>
                    <input type="hidden" name="exptime" value="<?php echo $exptime; ?>"/>
                    <input type="hidden" name="uhash" value="<?php echo wp_hash($username.$exptime); ?>"/>
                </form>
            </div>
        </div>
        
    </body>
</html>

<?php
    }
    
    function duo_options_page() {
?>
        <div class="wrap">
        <h2><?php _e('Duo Two-Factor Authentication Settings','duo_wordpress');?></h2>
        <form name="duo" method="post" action="options.php">
        <?php wp_nonce_field('update-options'); ?>
        <input type="hidden" name="action" value="update" />
        <input type="hidden" name="page_options" value="duo_integration_key,duo_secret_key,duo_api_host" />
        <table class="form-table">
        <tr valign="top">
        <th scope="row"><label for="duo_integration_key"><?php _e('Duo Integration Key','duo_wordpress');?></label></th>
        <td><input name="duo_integration_key" type="text" id="duo_integration_key" class="code" value="<?php echo get_option('duo_integration_key') ?>" size="40" /><br /></td>
        </tr>
        <tr valign="top">
        <th scope="row"><label for="duo_secret_key"><?php _e('Duo Secret Key','duo_wordpress');?></label></th>
        <td><input name="duo_secret_key" type="text" id="duo_secret_key" class="code" value="<?php echo get_option('duo_secret_key'); ?>" size="40" /><br /></td>
        </tr>
        <tr valign="top">
        <th scope="row"><label for="duo_api_host"><?php _e('Duo API Host','duo_wordpress');?></label></th>
        <td><input name="duo_api_host" type="text" id="duo_api_host" class="code" value="<?php if(get_option('duo_api_host')==false) echo 'api-eval.duosecurity.com'; else echo get_option('duo_api_host'); ?>" size="40" /><br /></td>
        </tr>
        <tr valign="top">
        <th scope="row"></th>
        <td><span class="description"><?php _e('You can retrieve your integration key and secret key by logging in to the Duo administrative interface.','duo_wordpress');?></span></td>
        </tr>
        <tr valign="top">
        <th scope="row"></th>
        <td><span class="description"><?php _e('If you don\'t yet have a Duo account, sign up now for free at <a target="_blank" href="http://www.duosecurity.com">http://www.duosecurity.com</a>','duo_wordpress');?></span></td>
        </tr>
        </table>
        <p class="submit">
        <input type="submit" name="Submit" value="<?php _e('Save Changes', 'duo_wordpress' ) ?>" />
        </p>
        </form>
        </div>

<?php
    }
    
    function duo_admin() {
        add_options_page('Duo Two-Factor', 'Duo Two-Factor', 'manage_options', 'duo_wordpress', 'duo_options_page');
    }

    function duo_authenticate_user($user="", $username="", $password="") {
        if (get_option("duo_secret_key") == "" || get_option("duo_integration_key" == "")) {
            return;
        }

        remove_action('authenticate', 'wp_authenticate_username_password', 20);

        if (isset($_POST['sig_response'])) {
            $sig = wp_hash($_POST['u'] . $_POST['exptime']);
            $expire = intval($_POST['exptime']);

            if (wp_hash($_POST['uhash']) == wp_hash($sig) && time() < $expire) {
                $user = get_userdatabylogin($_POST['u']);
                if ($user->user_login == Duo::verifyResponse(get_option('duo_secret_key'), $_POST['sig_response'])) {
                    wp_set_auth_cookie($user->ID);
                    wp_redirect($_POST['redirect_to']);
                    exit();
                }
            } else {
                $user = new WP_Error('Duo authentication_failed', __('<strong>ERROR</strong>: Failed or expired two factor authentication'));
                return $user;
            }
        }

        if (strlen($username) > 0) {
            $user = get_userdatabylogin($username);

            if (wp_check_password($password, $user->user_pass, $user-ID)) {
                duo_sign_request($user, $_POST['redirect_to']);
                exit();
            } else {
                $user = new WP_Error('authentication_failed', __('<strong>ERROR</strong>: Invalid username or incorrect password.'));
                return $user;
            }
        }
    }

    function duo_add_settings_link($links, $file) {
        static $this_plugin;
        if (!$this_plugin) $this_plugin = plugin_basename(__FILE__);
         
        if ($file == $this_plugin) {
            $settings_link = '<a href="options-general.php?page=duo_wordpress">'.__("Settings", "duo_wordpress").'</a>';
             array_unshift($links, $settings_link);
        }
        return $links;
    }

    add_filter('authenticate', 'duo_authenticate_user', 10, 3);
    add_filter('plugin_action_links', 'duo_add_settings_link', 10, 2 );
    add_action('admin_menu','duo_admin');
?>
