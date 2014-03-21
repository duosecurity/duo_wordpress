<?php
/*
Plugin Name: Duo Two-Factor Authentication
Plugin URI: http://wordpress.org/extend/plugins/duo-wordpress/
Description: This plugin enables Duo two-factor authentication for WordPress logins.
Version: 2.0
Author: Duo Security
Author URI: http://www.duosecurity.com
License: GPL2
*/

/*
Copyright 2014 Duo Security <duo_web@duosecurity.com>

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

    require_once('duo_web/duo_web.php');
    $DuoAuthCookieName = 'duo_wordpress_auth_cookie';
    $DuoDebug = false;

    function duo_sign_request($user, $redirect) {
        $ikey = duo_get_option('duo_ikey');
        $skey = duo_get_option('duo_skey');
        $host = duo_get_option('duo_host');
       
        $username = $user->user_login;

        $duo_time = duo_get_time();
        $request_sig = Duo::signRequest($ikey, $skey, wp_salt(), $username, $duo_time);

        duo_debug_log("Displaying iFrame. Username: $username cookie domain: " . COOKIE_DOMAIN . " redirect_to_url: $redirect ikey: $ikey host: $host duo_time: $duo_time");
        duo_debug_log("Duo request signature: $request_sig");

?>
    <html>
        <head>
            <meta http-equiv="X-UA-Compatible" content="IE=edge">
            <?php
                global $wp_version;
                if(version_compare($wp_version, "3.3", "<=")){
                    echo '<link rel="stylesheet" type="text/css" href="' . admin_url('css/login.css') . '" />';
                }
                else if(version_compare($wp_version, "3.7", "<=")){
                    echo '<link rel="stylesheet" type="text/css" href="' . admin_url('css/wp-admin.css') . '" />';
                    echo '<link rel="stylesheet" type="text/css" href="' . admin_url('css/colors-fresh.css') . '" />';
                }
                else {
                    echo '<link rel="stylesheet" type="text/css" href="' . admin_url('css/wp-admin.css') . '" />';
                    echo '<link rel="stylesheet" type="text/css" href="' . admin_url('css/colors.css') . '" />';
                }
            ?>

            <style>
                body {
                    background: #f1f1f1;
                }
                .centerHeader {
                    width: 100%;
                    padding-top: 8%;
                }
                #WPLogo {
                    width: 100%;
                }
                #duo_iframe {
                    width: 90%;
                    height: 500px;
                    max-width: 620px;
                    display: table;
                    margin: 0 auto;
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
                'post_action': '<?php echo esc_url(site_url('wp-login.php', 'login_post')) ?>',
                'sig_request':<?php echo "'" . $request_sig . "'"; ?>
            });
            </script>

            <h1 class="centerHeader">
                <a href="http://wordpress.org/" id="WPLogo" title="Powered by WordPress"><?php echo get_bloginfo('name'); ?></a>
            </h1>
            <iframe id="duo_iframe" frameborder="0" allowtransparency="true"></iframe>
            <form method="POST" style="display:none;" id="duo_form">
                <input type="hidden" name="rememberme" value="<?php echo esc_attr($_POST['rememberme'])?>"/>
                <?php
                if (isset($_REQUEST['interim-login'])){
                    echo '<input type="hidden" name="interim-login" value="1"/>';
                }
                else {
                    echo '<input type="hidden" name="redirect_to" value="' . esc_attr($redirect) . '"/>';
                }
                ?>
            </form>
        </body>
    </html>
<?php
    }

    function duo_get_roles(){
        global $wp_roles;
        // $wp_roles may not be initially set if wordpress < 3.3
        $wp_roles = isset($wp_roles) ? $wp_roles : new WP_Roles();
        return $wp_roles;
    }

    function duo_auth_enabled(){
        if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) { 
            duo_debug_log('Found an XMLRPC request. XMLRPC is allowed for this site. Skipping second factor');
            return false; //allows the XML-RPC protocol for remote publishing
        }

        if (duo_get_option('duo_ikey', '') == '' || duo_get_option('duo_skey', '') == '' ||
            duo_get_option('duo_host', '') == '') {
            return false;
        }
        return true;
    }

    function duo_role_require_mfa($user){
        $wp_roles = duo_get_roles();
        foreach ($wp_roles->get_names() as $k=>$r) {
            $all_roles[$k] = $r;
        }

        $duo_roles = duo_get_option('duo_roles', $all_roles); 

        /*
         * WordPress < 3.3 does not include the roles by default
         * Create a User object to get roles info
         * Don't use get_user_by()
         */
        if (!isset($user->roles)){
            $user = new WP_User(0, $user->user_login);
        }

        /*
         * Mainly a workaround for multisite login:
         * if a user logs in to a site different from the one 
         * they are a member of, login will work however
         * it appears as if the user has no roles during authentication
         * "fail closed" in this case and require duo auth
         */
        if(empty($user->roles)) {
            return true;
        }

        foreach ($user->roles as $role) {
            if (array_key_exists($role, $duo_roles)) {
                return true;
            }
        }
        return false;
    }

    function duo_start_second_factor($user, $redirect_to=NULL){
        if (!$redirect_to){
            // Some custom themes do not provide the redirect_to value
            // Admin page is a good default
            $redirect_to = isset( $_POST['redirect_to'] ) ? $_POST['redirect_to'] : admin_url();
        }

        wp_logout();
        duo_sign_request($user, $redirect_to);
        exit();
    }
    
    function duo_authenticate_user($user="", $username="", $password="") {
        // play nicely with other plugins if they have higher priority than us
        if (is_a($user, 'WP_User')) {
            return $user;
        }

        if (! duo_auth_enabled()){
            duo_debug_log('Duo not enabled, skipping 2FA.');
            return;
        }

        if (isset($_POST['sig_response'])) {
            // secondary auth
            remove_action('authenticate', 'wp_authenticate_username_password', 20);

            $duo_time = duo_get_time();
            $username = Duo::verifyResponse(duo_get_option('duo_ikey'),
                                            duo_get_option('duo_skey'),
                                            wp_salt(),
                                            $_POST['sig_response'],
                                            $duo_time);
            if ($username) {
                // Don't use get_user_by(). It doesn't return a WP_User object if wordpress version < 3.3
                $user = new WP_User(0, $username);

                duo_set_cookie($user);

                duo_debug_log("Second factor successful for user: $username");
                return $user;
            } else {
                $user = new WP_Error('Duo authentication_failed',
                                     __('<strong>ERROR</strong>: Failed or expired two factor authentication'));
                return $user;
            }
        }

        if (strlen($username) > 0) {
            // primary auth
            // Don't use get_user_by(). It doesn't return a WP_User object if wordpress version < 3.3
            $user = new WP_User(0, $username);
            if (!$user) {
                error_log("Failed to retrieve WP user $username");
                return;
            }
            if(!duo_role_require_mfa($user)){
                duo_debug_log("Skipping 2FA for user: $username with roles: " . print_r($user->roles, true));
                return;
            }

            remove_action('authenticate', 'wp_authenticate_username_password', 20);
            $user = wp_authenticate_username_password(NULL, $username, $password);
            if (!is_a($user, 'WP_User')) {
                // on error, return said error (and skip the remaining plugin chain)
                return $user;
            } else {
                duo_debug_log("Primary auth succeeded, starting second factor for $username");
                duo_start_second_factor($user);
            }
        }
        duo_debug_log('Starting primary authentication');
    }

    function duo_settings_page() {
        duo_debug_log('Displaying duo setting page');
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
                <input name="Submit" type="submit" class="button primary-button" value="<?php esc_attr_e('Save Changes'); ?>" />
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
        echo "<input id='duo_skey' name='duo_skey' size='40' type='password' value='$skey' autocomplete='off' />";
    }

    function duo_settings_host() {
        $host = esc_attr(duo_get_option('duo_host'));
        echo "<input id='duo_host' name='duo_host' size='40' type='text' value='$host' />";
    }

    function duo_settings_roles() {
        $wp_roles = duo_get_roles();
        $roles = $wp_roles->get_names();
        $newroles = array();
        foreach($roles as $key=>$role) {
            $newroles[before_last_bar($key)] = before_last_bar($role);
        }

        $selected = duo_get_option('duo_roles', $newroles);

        foreach ($wp_roles->get_names() as $key=>$role) {
            //create checkbox for each role
?>
            <input id="duo_roles" name='duo_roles[<?php echo $key; ?>]' type='checkbox' value='<?php echo $role; ?>'  <?php if(in_array($role, $selected)) echo 'checked'; ?> /> <?php echo $role; ?> <br />
<?php
        }
    }

    function duo_roles_validate($options) {
        //return empty array
        if (!is_array($options) || empty($options) || (false === $options)) {
            return array();
        }

        $wp_roles = duo_get_roles();

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
        echo "<p>See the <a target='_blank' href='https://www.duosecurity.com/docs/wordpress'>Duo for WordPress guide</a> to enable Duo two-factor authentication for your WordPress logins.</p>";
        echo '<p>You can retrieve your integration key, secret key, and API hostname by logging in to the Duo administrative interface.</p>';
        echo '<p>Note: After enabling the plugin, you will be immediately prompted for second factor authentication.</p>';
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
            $val = "checked";
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


    function duo_add_site_option($option, $value = '') {
        // Add multisite option only if it doesn't exist already
        // With Wordpress versions < 3.3, calling add_site_option will override old values
        if (duo_get_option($option) === FALSE){
            add_site_option($option, $value);
        }
    }

    function duo_admin_init() {
        if (is_multisite()) {
            $wp_roles = duo_get_roles();
            $roles = $wp_roles->get_names();
            $allroles = array();
            foreach($roles as $key=>$role) {
                $allroles[before_last_bar($key)] = before_last_bar($role);
            }
            
            duo_add_site_option('duo_ikey', '');
            duo_add_site_option('duo_skey', '');
            duo_add_site_option('duo_host', '');
            duo_add_site_option('duo_roles', $allroles);
            duo_add_site_option('duo_xmlrpc', 'off');
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
            $result = update_site_option('duo_xmlrpc', $xmlrpc);
        }
        else {
            $result = update_site_option('duo_xmlrpc', 'on');
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
        $time = NULL;
        if (!extension_loaded('openssl')) {
            //fall back to local time
            error_log('SSL is disabled. Can\'t fetch Duo server time.');
        }
        else {
            $duo_url = 'https://' . duo_get_option('duo_host') . '/auth/v2/ping';
            $cert_file = dirname(__FILE__) . '/duo_web/ca_certs.pem';
            if( ini_get('allow_url_fopen') ) {
                $time =  duo_get_time_fopen($duo_url, $cert_file);
            } 
            else if(in_array('curl', get_loaded_extensions())){
                $time = duo_get_time_curl($duo_url, $cert_file);
            }
            else{
                $time = duo_get_time_WP_HTTP($duo_url);
            }
        }

        //if all fails, use local time
        $time = ($time != NULL ? $time : time());
        return $time;
    }

    function duo_get_time_fopen($duo_url, $cert_file){
        $settings = array(
                        'http'=>array(
                            'method' => 'GET'
                        ),
                        'ssl'=>array(
                            'allow_self_signed'=>false,
                            'verify_peer'=>true,
                            'cafile'=>$cert_file
                        )
        );

        if ( defined('WP_PROXY_HOST') && defined('WP_PROXY_PORT')) {
            $settings['http']['proxy'] = 'tcp://' . WP_PROXY_HOST . ':' . WP_PROXY_PORT;
        }

        $context = stream_context_create($settings);
        $response = json_decode(file_get_contents($duo_url, false, $context), true);
        if (!$response){
            return NULL;
        }
        $time = (int)$response['response']['time'];

        return $time;
    }

    function duo_get_time_curl($duo_url, $cert_file) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $duo_url);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, TRUE);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_CAINFO, $cert_file);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);

        if ( defined('WP_PROXY_HOST') && defined('WP_PROXY_PORT')) {
            curl_setopt( $handle, CURLOPT_PROXYTYPE, CURLPROXY_HTTP );
            curl_setopt( $handle, CURLOPT_PROXY, WP_PROXY_HOST );
            curl_setopt( $handle, CURLOPT_PROXYPORT, WP_PROXY_PORT );
        }

        $response =json_decode(curl_exec($ch), true);
        curl_close ($ch);
        if (!$response){
            return NULL;
        }
        $time = (int)$response['response']['time'];
        return $time;
    }

    // Uses Worpress HTTP, problem is that we can't specify our SSL cert here.
    // Servers with out of date root certs may fail.
    function duo_get_time_WP_HTTP($duo_url){
        if(!class_exists('WP_Http')){
            include_once(ABSPATH . WPINC . '/class-http.php');
        }

        $args = array(
            'method'      =>    'GET',
            'blocking'    =>    true,
            'sslverify'   =>    true,
        );
        $response = wp_remote_get($duo_url, $args);
        if(is_wp_error($response)){
            $error_message = $response->get_error_message();
            error_log("Could not fetch Duo server time: $error_message");
            return NULL;
        }
        else {
            $body = json_decode(wp_remote_retrieve_body($response), true);
            $time = (int)$body['response']['time'];
            return $time;
        }
    }

    function duo_set_cookie($user){

        global $DuoAuthCookieName;
        $ikey_b64 = base64_encode(duo_get_option('duo_ikey'));
        $username_b64 = base64_encode($user->user_login);
        $expire = strtotime('+48 hours');
        $val = base64_encode(sprintf("%s|%s|%s|%s", $DuoAuthCookieName, $username_b64, $ikey_b64, $expire)); 
        $sig = duo_hash_hmac($val);
        $cookie = sprintf("%s|%s", $val, $sig);

        $cookie_set = setcookie($DuoAuthCookieName, $cookie, 0, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true);
        if (! $cookie_set){
            error_log("Failed to set duo cookie for user: $user->user_login");
        }
        duo_debug_log("Set Duo cookie for user: $user->user_login path: " . COOKIEPATH . " on domain: " . COOKIE_DOMAIN);
    }

    function duo_unset_cookie(){
        global $DuoAuthCookieName;
        setcookie($DuoAuthCookieName, '', strtotime('-1 day'), COOKIEPATH, COOKIE_DOMAIN);
        duo_debug_log("Unset Duo cookie for path: " . COOKIEPATH . " on domain: " . COOKIE_DOMAIN);
    }

    function duo_verify_sig($cookie, $u_sig){
        $sig = duo_hash_hmac($cookie);
        if (duo_hash_hmac($sig) === duo_hash_hmac($u_sig)) {
            return true;
        }
        return false;
    }

    function duo_verify_cookie($user){
    /*
        Return true if Duo cookie is valid, false otherwise
    */
        global $DuoAuthCookieName;
        if(!isset($_COOKIE[$DuoAuthCookieName])){
            error_log("Duo cookie not set. Start two factor authentication");
            return false;
        }

        $cookie_list = explode('|', $_COOKIE[$DuoAuthCookieName]);
        if (count($cookie_list) !== 2){
            error_log('Invalid Duo cookie');
            return false;
        }
        list($u_cookie_b64, $u_sig) = $cookie_list;
        if (!duo_verify_sig($u_cookie_b64, $u_sig)){
            error_log('Duo cookie signature mismatch');
            return false;
        }

        $cookie_content = explode('|', base64_decode($u_cookie_b64));
        if (count($cookie_content) !== 4){
            error_log('Invalid field count in Duo cookie');
            return false;
        }
        list($cookie_name, $cookie_username_b64, $cookie_ikey_b64, $expire) = $cookie_content;
        //Check cookie values
        if ($cookie_name !== $DuoAuthCookieName ||
            base64_decode($cookie_username_b64) !== $user->user_login ||
            base64_decode($cookie_ikey_b64) !== duo_get_option('duo_ikey')){
            error_log('Invalid Duo cookie content');
            return false;
        }

        $expire = intval($expire);
        if ($expire < strtotime('now')){
            error_log('Duo cookie expired');
            return false;
        }
        return true;
    }

    function duo_get_uri(){
        // Workaround for IIS which may not set REQUEST_URI, or QUERY parameters
        if (!isset($_SERVER['REQUEST_URI']) ||
            (!empty($_SERVER['QUERY_STRING']) && !strpos($_SERVER['REQUEST_URI'], '?', 0))) {
            $current_uri = substr($_SERVER['PHP_SELF'],1);
            if (isset($_SERVER['QUERY_STRING']) AND $_SERVER['QUERY_STRING'] != '') {
                $current_uri .= '?'.$_SERVER['QUERY_STRING'];
            }
            return $current_uri;
        }
        else {
            return $_SERVER['REQUEST_URI'];
        }
    }

    function duo_verify_auth(){
    /*
        Verify the user is authenticated with Duo. Start 2FA otherwise
    */
        if (! duo_auth_enabled()){
            duo_debug_log('Duo not enabled, skip cookie check.');
            return;
        }

        if(is_user_logged_in()){
            $user = wp_get_current_user();
            duo_debug_log("Verifying second factor for user: $user->user_login URL: " .  duo_get_uri() . ' cookie domain: ' . COOKIE_DOMAIN);
            if (duo_role_require_mfa($user) and !duo_verify_cookie($user)){
                duo_debug_log("Duo cookie invalid for user: $user->user_login");
                duo_start_second_factor($user, duo_get_uri());
            }
            duo_debug_log("User $user->user_login allowed");
        }
    }

    function duo_debug_log($message) {
        global $DuoDebug;
        if ($DuoDebug) {
            error_log('Duo debug: ' . $message);
        }
    }

    function duo_hash_hmac($data){
        return hash_hmac('sha1', $data, wp_salt());
    }

    /*-------------XML-RPC Features-----------------*/
    
    if(duo_get_option('duo_xmlrpc', 'off') == 'off') {
        add_filter( 'xmlrpc_enabled', '__return_false' );
    }

    /*-------------Register WordPress Hooks-------------*/

    if (!is_multisite()) {
        add_filter('plugin_action_links', 'duo_add_link', 10, 2 );
    }

    add_action('init', 'duo_verify_auth', 10);

    add_action('clear_auth_cookie', 'duo_unset_cookie', 10);

    add_filter('authenticate', 'duo_authenticate_user', 10, 3);
    
    //add single-site submenu option
    add_action('admin_menu', 'duo_add_page');

    // Custom fields in network settings
    add_action('wpmu_options', 'duo_mu_options');
    add_action('update_wpmu_options', 'duo_update_mu_options');

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
