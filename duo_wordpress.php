<?php
/*
Plugin Name: Duo Two-Factor Authentication
Plugin URI: https://github.com/duosecurity/duo_wordpress
Description: This plugin enables Duo two-factor authentication for WordPress logins.
Version: 1.3.2
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
        $ikey = get_option('duo_ikey');
        $skey = get_option('duo_skey');
        $host = get_option('duo_host');
       
        $username = $user->user_login;

        $request_sig = Duo::signRequest($ikey, $skey, $username);

        $exptime = time() + 3600; // let the duo login form expire within 1 hour
?>
    <html>
        <head>
            <link rel="stylesheet" type="text/css" href="<?php echo admin_url('css/login.css'); ?>" />
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
                'post_action':'wp-login.php',
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
        if ( defined('XMLRPC_REQUEST') && XMLRPC_REQUEST ) 
            return; //allows the XML-RPC protocol for remote publishing

        if (get_option("duo_ikey", "") == "" || get_option("duo_skey", "") == "" || get_option("duo_host", "") == "") {
            return;
        }

        if (isset($_POST['sig_response'])) {
            remove_action('authenticate', 'wp_authenticate_username_password', 20);
            $sig = wp_hash($_POST['u'] . $_POST['exptime']);
            $expire = intval($_POST['exptime']);

            if (wp_hash($_POST['uhash']) == wp_hash($sig) && time() < $expire) {
                $user = get_userdatabylogin($_POST['u']);

                if ($user->user_login == Duo::verifyResponse(get_option('duo_skey'), $_POST['sig_response'])) {
                    wp_set_auth_cookie($user->ID);
                    wp_safe_redirect($_POST['redirect_to']);
                    exit();
                }
            } else {
                $user = new WP_Error('Duo authentication_failed', __('<strong>ERROR</strong>: Failed or expired two factor authentication'));
                return $user;
            }
        }

        if (strlen($username) > 0) {
            $user = get_userdatabylogin($username);

            $usr = new WP_User($user->ID);

			global $wp_roles;
			foreach ($wp_roles->get_names() as $r) {
				$all_roles[strtolower(before_last_bar($r))] = ucfirst(before_last_bar($r));
			}

            $duo_roles = get_option('duo_roles', $all_roles); 
            $duo_auth = false;

            if (!empty($usr->roles) && is_array($usr->roles)) {
                foreach ($usr->roles as $role) {
                    if (array_key_exists(strtolower(before_last_bar($role)), $duo_roles)) {
                        $duo_auth = true;
                    }
                }
            }

            if (!$duo_auth) {
                return;
            }

            remove_action('authenticate', 'wp_authenticate_username_password', 20);

            if (duo_check_login($username, $password, $user->ID)) {
                duo_sign_request($user, $_POST['redirect_to']);
                exit();
            } else {
                $user = new WP_Error('authentication_failed', __('<strong>ERROR</strong>: Invalid username or incorrect password.'));
                return $user;
            }
        }
    }

	/* 
	 * function duo_check_login
	 * args: username and password
	 * returns: true - if password matches one on file for user
	 * returns: false - all other cases
	 */
	function duo_check_login($username, $password) {
		$user = get_userdatabylogin($username);

		if (wp_check_password($password, $user->user_pass, $user->ID)) {
			return true;
		}

		return false;
	}

    function duo_settings_page() {
?>
    <div class="wrap">
        <h2>Duo Two-Factor Authentication</h2>
        <form action="options.php" method="post">
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
        $ikey = esc_attr(get_option('duo_ikey'));
        echo "<input id='duo_ikey' name='duo_ikey' size='40' type='text' value='$ikey' />";
    }

    function duo_settings_skey() {
        $skey = esc_attr(get_option('duo_skey'));
        echo "<input id='duo_skey' name='duo_skey' size='40' type='text' value='$skey' />";
    }

    function duo_settings_host() {
        $host = esc_attr(get_option('duo_host'));
        echo "<input id='duo_host' name='duo_host' size='40' type='text' value='$host' />";
    }

    function duo_settings_roles() {
        global $wp_roles;

        $roles = $wp_roles->get_names();
        $newroles = array();
        foreach($roles as $key=>$role) {
            $newroles[before_last_bar($key)] = before_last_bar($role);
        }

        $selected = get_option('duo_roles', $newroles);

        foreach ($wp_roles->get_names() as $role) {
            //create checkbox for each role
?>
    <input id="duo_roles" name='duo_roles[<?php echo strtolower(before_last_bar($role)); ?>]' type='checkbox' value='<?php echo before_last_bar($role); ?>'  <?php if(in_array(before_last_bar($role), $selected)) echo 'checked="checked"'; ?> /> <?php echo before_last_bar($role); ?> <br />
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
            if (!in_array(before_last_bar($opt), $valid_roles)) {
                unset($options[before_last_bar($opt)]);
            }
        }
        return $options;
    }

    function duo_settings_text() {
        echo "<p>If you don't yet have a Duo account, sign up now for free at <a target='_blank' href='http://www.duosecurity.com'>http://www.duosecurity.com</a>.</p>";
        echo "<p>To enable Duo two-factor authentication for your WordPress login, you need to configure your integration settings.</p>";
        echo "<p>You can retrieve your integration key, secret key, and API hostname by logging in to the Duo administrative interface.</p>";
    }

    function duo_ikey_validate($ikey){
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


    function duo_admin_init() {
        add_settings_section('duo_settings', 'Main Settings', 'duo_settings_text', 'duo_settings');
        add_settings_field('duo_ikey', 'Integration key', 'duo_settings_ikey', 'duo_settings', 'duo_settings');
        add_settings_field('duo_skey', 'Secret key', 'duo_settings_skey', 'duo_settings', 'duo_settings');
        add_settings_field('duo_host', 'API hostname', 'duo_settings_host', 'duo_settings', 'duo_settings');
        add_settings_field('duo_roles', 'Enable for roles:', 'duo_settings_roles', 'duo_settings', 'duo_settings');
        register_setting('duo_settings', 'duo_ikey', 'duo_ikey_validate');
        register_setting('duo_settings', 'duo_skey', 'duo_skey_validate');
        register_setting('duo_settings', 'duo_host');
        register_setting('duo_settings', 'duo_roles', 'duo_roles_validate');
    }

    function duo_add_page() {
        add_options_page('Duo Two-Factor', 'Duo Two-Factor', 'manage_options', 'duo_wordpress', 'duo_settings_page');
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

    /*-------------XML-RPC Features-----------------*/
    

    /*-------------Register WordPress Hooks-------------*/

    add_filter('authenticate', 'duo_authenticate_user', 10, 3);
    add_filter('plugin_action_links', 'duo_add_link', 10, 2 );
    add_action('admin_menu', 'duo_add_page');
    add_action('admin_init', 'duo_admin_init');

?>
