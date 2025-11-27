<?php
/**
 * Plugin Name: Mnml Login
 * Plugin URI:  https://github.com/andrewklimek/mnml-login
 * Description: Custom login form with optional 2FA (email/SMS codes, magic links) for private portals and regular sites, with bot deterrence and theme styling.
 * Version:     1.0.7
 * Author:      Andrew Klimek
 * Author URI:  https://github.com/andrewklimek
 * License:     GPLv2 or later
 * License URI: http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 */

namespace MnmlLogin;

defined('ABSPATH') || exit;

// test
// add_filter('auth_cookie_expiration', function ($length) { return 120; });

// Load Twilio if configured
$settings = (object) get_option('mnml_login', []);
if (! empty($settings->twilio_account_sid) && ! empty($settings->twilio_api_sid) && ! empty($settings->twilio_api_secret) && (! empty($settings->twilio_from) || ! empty($settings->twilio_messaging_service_sid))) {
    require __DIR__ . '/twilio.php';
}

// Register shortcode for login form
add_shortcode('mnml_login', __NAMESPACE__ . '\login_shortcode');

// REST API for auth, token, magic link, settings, and logout
add_action('rest_api_init', __NAMESPACE__ . '\register_api_endpoints');

// Handle magic links and logout
add_action('parse_request', __NAMESPACE__ . '\magic_link_handler', 8);
add_action('parse_request', __NAMESPACE__ . '\logout_handler', 9);

// Block wp-login.php
add_action('init', __NAMESPACE__ . '\block_wp_login');

// Settings page
add_action('admin_menu', __NAMESPACE__ . '\admin_menu');
add_filter('plugin_action_links_' . plugin_basename(__FILE__), __NAMESPACE__ . '\add_settings_link', 10, 2);

// Rewrite logout URL
add_filter('logout_url', __NAMESPACE__ . '\custom_logout_url', 10, 2);

// Customize login URL for interim logins
add_filter('login_url', __NAMESPACE__ . '\custom_login_url', 10, 3);

// I think this periodically sends you to wp-login.php to confirm the email, and that url is blocked.
add_filter( 'admin_email_check_interval', '__return_false' );

function get_login_page_url() {
    $pages = get_posts([
        'post_type'   => 'page',
        'post_status' => 'publish',
        'meta_query'  => [
            [
                'key'     => '_wp_page_template',
                'compare' => 'EXISTS',
            ],
        ],
        's'           => '[mnml_login]',
        'numberposts' => 1,
    ]);
    return ! empty($pages) ? get_permalink($pages[0]) : site_url();
}


// Redirect all URLs to homepage with login form
function redirect_to_homepage_login() {

    if ( is_user_logged_in() ) return;
    if (is_robots() || is_favicon()) return;

    // Skip for logout or magic link requests
    if ((isset($_GET['action']) && $_GET['action'] === 'logout') || !empty($_GET['tfal'])) return;

    $settings = (object) get_option('mnml_login', []);
    if (empty($settings->private_site)) return;

    if ( is_front_page() ) {

        // let the theme's template load normally (user must add [mnml_login] to homepage content)
        if (!empty($settings->use_custom_homepage)) return;

        // Set cache headers
        if (isset($_GET['action']) && in_array($_GET['action'], ['lostpassword', 'rp'], true) || isset($_GET['interim-login'])) {
            header('Cache-Control: no-store');
        } else {
            header('Cache-Control: public, max-age=3600');
        }

        status_header(200);
        echo '<!DOCTYPE html><html lang=en>';
        echo '<meta name=viewport content="width=device-width, initial-scale=1">';
        echo '<meta name=robots content="noindex, nofollow">';
        if (!empty($settings->allow_api_discovery)) rest_output_link_wp_head();
        echo '<title>' . esc_html(get_bloginfo('name', 'display')) . '</title>';

        // do styling
        $add_css = function( $url, $path ) {
            if ( file_exists( $path ) ) echo '<link rel=stylesheet href="'. esc_url( $url ) .'" />';
        };
        $parent_uri = get_template_directory_uri();
        $child_uri  = get_stylesheet_directory_uri();
        $add_css( $parent_uri . '/style.css', get_template_directory() . '/style.css' );
        $add_css( $parent_uri . '/login.css', get_template_directory() . '/login.css' );
        if ( $parent_uri !== $child_uri ) {// if child theme in use
            $add_css( $child_uri . '/style.css', get_stylesheet_directory() . '/style.css' );
            $add_css( $child_uri . '/login.css', get_stylesheet_directory() . '/login.css' );
        }

        echo do_shortcode('[mnml_login]');
        exit;
    }

    // Capture the requested URL for redirect_to
    $redirect = esc_url_raw($_SERVER['REQUEST_URI']);

    // Redirect to homepage with redirect_to parameter
    $login_url = add_query_arg(['redirect_to' => urlencode($redirect)], site_url());
    wp_safe_redirect($login_url);
    exit;
}
add_action('template_redirect', __NAMESPACE__ . '\redirect_to_homepage_login', 8);

// Conditional shortcodes for logged-in/logged-out content
add_shortcode('mnml_logged_in', function ($atts, $content = null) {
    return is_user_logged_in() ? do_shortcode($content) : '';
});
add_shortcode('mnml_logged_out', function ($atts, $content = null) {
    return !is_user_logged_in() ? do_shortcode($content) : '';
});

// Login shortcode
function login_shortcode( $atts ) {
    
    if (is_user_logged_in()) {
        return '';
    }
    $settings = (object) get_option('mnml_login', []);

    $redirect = $_GET['redirect_to'] ?? $atts['redirect'] ?? '';

    $class = isset($atts['class']) ? ' class="'. $atts['class'] .'"' : '';

    ob_start();

    echo "<style>";
    if ( empty( $atts['no_styling'] ) ) {
        echo "#mnml-login{max-width:400px;margin:50px auto;padding:20px}";
        echo ".mnml-input{width:100%;padding:8px;margin:5px 0}";
    }
    echo "#mnml-2fa-section,.mnml-link-sent #mnml-login-section,#simple-login-form,.mnml-no-2facode{display:none}";
    echo ".mnml-link-sent #mnml-2fa-section{display:block}";
    ?>
    #mnml2fac {
        border: none;
        outline: none;
        font-size: 2em;
        letter-spacing: 1ch;
        width: 12ch;
        margin: auto;
        display: block;
    }
    <?php
    echo "</style>";
    ?>
<form id=simple-login-form method=post action="<?php echo rest_url('mnml_login/v1/simple_login'); ?>">
    <input type=text  name=log id=user_login class=input>
    <input type=password name=pwd id=user_pass class=input>
    <input type=submit value=Login>
</form>
<div id=mnml-login<?php echo $class; ?>>
    <p id=mnml-login-msg class=mnml-login-msg></p>
    <form id=mnml-login-form method=post>
        <?php if (isset($_GET['action']) && $_GET['action'] === 'lostpassword'): ?>
            <div id=mnml-login-section>
                <p><label for=mnml-user-login>Username or Email<br>
                    <input type=text name=user_login id=mnml-user-login class=mnml-input size=20 autocomplete=username>
                </label></p>
                <p><input type=submit id=mnml-submit class=mnml-button value="Get New Password" disabled>
                <input type=hidden name=action value=lostpassword>
                <input type=hidden name=login_token id=mnml-token>
            </div>
        <?php elseif (isset($_GET['action']) && $_GET['action'] === 'rp' && isset($_GET['key']) && isset($_GET['login'])): ?>
            <div id=mnml-login-section>
                <p><label for=mnml-pass1>New Password<br>
                    <input type=password name=pass1 id=mnml-pass1 class=mnml-input size=20 autocomplete=new-password required>
                </label></p>
                <p><label for=mnml-pass2>Confirm Password<br>
                    <input type=password name=pass2 id=mnml-pass2 class=mnml-input size=20 autocomplete=new-password required>
                </label></p>
                <p><input type=submit id=mnml-submit class=mnml-button value="Reset Password" disabled>
                <input type=hidden name=action value=resetpassword>
                <input type=hidden name=rp_key value="<?php echo esc_attr($_GET['key']); ?>">
                <input type=hidden name=rp_login value="<?php echo esc_attr($_GET['login']); ?>">
                <input type=hidden name=login_token id=mnml-token>
            </div>
        <?php elseif (isset($_GET['interim-login'])): ?>
            <div id=mnml-login-section>
                <p><label for=mnml2falog>Username or Email<br>
                    <input type=text name=mnml2falog id=mnml2falog class=mnml-input size=20 autocapitalize=off autocomplete="email tel" required>
                </label></p>
                <?php if ($settings->two_factor_auth === 'code' || $settings->two_factor_auth === 'none'): ?>
                <p><label for=mnml-pwd>Password<br>
                    <input type=password name=pwd id=mnml-pwd class=mnml-input size=20 autocomplete=current-password required>
                </label></p>
                <?php endif; ?>
                <?php if ( strpos($settings->two_factor_auth, 'code') !== false ): ?>
                <div id=mnml-2fa-section>
                    <p><label for=mnml2fac>Security Code<br>
                        <input inputmode=numeric maxlength=6 name=mnml2fac id=mnml2fac class=mnml-input autocomplete=one-time-code placeholder="------">
                    </label></p>
                </div>
                <?php endif; ?>
                <p><input type=submit id=mnml-submit class=mnml-button value="Log In" disabled>
                <input type=hidden name=interim-login value=1>
                <input type=hidden name=login_token id=mnml-token>
                <input type=hidden name=mnml2fak id=mnml2fak>
            </div>
        <?php else: ?>
            <div id=mnml-login-section>
                <p><label for=mnml2falog>Username or Email<br>
                    <input type=text name=mnml2falog id=mnml2falog class=mnml-input size=20 autocapitalize=off autocomplete="email tel username" required>
                </label></p>
                <?php if ($settings->two_factor_auth === 'code' || $settings->two_factor_auth === 'none'): ?>
                <p><label for=mnml-pwd>Password<br>
                    <input type=password name=pwd id=mnml-pwd class=mnml-input size=20 autocomplete=current-password required>
                </label></p>
                <?php endif; ?>
            </div>
            <?php if ( strpos($settings->two_factor_auth, 'code') !== false ): ?>
            <div id=mnml-2fa-section>
                <p><label for=mnml2fac>security code:<br>
                    <input inputmode=numeric maxlength=6 name=mnml2fac id=mnml2fac class=mnml-input autocomplete=one-time-code placeholder="------">
                </label></p>
                <p id=mnml-countdown></p>
            </div>
            <?php endif; ?>
            <p><label><input name=rememberme type=checkbox id=mnml-rememberme value=forever> Remember Me</label></p>
            <p><input type=submit id=mnml-submit class=mnml-button value="Log In" disabled>
            <input type=hidden name=login_token id=mnml-token>
            <input type=hidden name=mnml2fak id=mnml2fak>
            <?php if ($redirect) : ?>
                <input type=hidden name=redirect_to value="<?php echo sanitize_url($redirect); ?>">
            <?php endif; ?>
        <?php endif; ?>
    </form>
    <?php if ( !isset($_GET['interim-login']) && ($settings->two_factor_auth === 'code' || $settings->two_factor_auth === 'none') ): ?>
    <p><a href="<?php echo esc_url(isset($_GET['action']) && $_GET['action'] === 'lostpassword' ? remove_query_arg('action', esc_url_raw($_SERVER['REQUEST_URI'])) : add_query_arg(['action' => 'lostpassword'], esc_url_raw($_SERVER['REQUEST_URI']))); ?>">
    <?php echo isset($_GET['action']) && $_GET['action'] === 'lostpassword' ? 'Log in' : 'Lost Password'; ?></a></p>
    <?php endif; ?>
</div>
<script>
document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('mnml-login-form');
    const msgEl = document.getElementById('mnml-login-msg');
    let hasInteracted = false, tokenFetched = true;

    // Interaction pre-check
    form.querySelectorAll('#mnml2falog, #mnml2fac, #mnml-user-login').forEach(input => {
        input.addEventListener('keydown', () => {
            hasInteracted = true;
            form.querySelectorAll('#mnml-submit').forEach(el => el.removeAttribute('disabled'));
        });
    });
    document.addEventListener('mousemove', () => hasInteracted = true, { once: true });

    <?php if (! empty($settings->enable_bot_protection)): ?>
    tokenFetched = false;
    // Fetch token
    const fetchToken = () => {
        fetch('<?php echo rest_url('mnml_login/v1/get_token'); ?>', {
            method: 'GET',
            credentials: 'same-origin'
        })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                form.querySelectorAll('#mnml-token').forEach(el => el.value = data.data.token);
                form.querySelectorAll('#mnml2fak').forEach(el => el.value = data.data.token);
                tokenFetched = true;
                if (hasInteracted) {
                    form.querySelectorAll('#mnml-submit').forEach(el => el.removeAttribute('disabled'));
                }
            } else {
                msgEl.textContent = data.message || 'Failed to load form token.';
            }
        })
        .catch(() => {
            msgEl.textContent = 'Error loading form. Please enable JavaScript.';
        });
    };

    if (hasInteracted) {
        fetchToken();
    } else {
        setTimeout(fetchToken, 2000);
    }
    <?php else: ?>
    form.querySelectorAll('#mnml-submit').forEach(el => el.removeAttribute('disabled'));
    <?php endif; // enable_bot_protection ?>

    // auto submit after 6 characters
    const codeInput = document.getElementById('mnml2fac');
    if (codeInput) {
        codeInput.addEventListener('input', () => {
            if (codeInput.value.length >= 6) {
                form.requestSubmit();
            }
        });
    }

    // startCountdown
    // const resendLink = document.getElementById('mnml-resend-code');
    const countdownEl = document.getElementById('mnml-countdown');
    let timer;
    const startCountdown = () => {
        let sec = 300;
        // resendLink.style.display = 'none';
        // countdownEl.style.display = 'inline';
        countdownEl.textContent = 'Code expires in 5:00';
        clearInterval(timer);
        timer = setInterval(() => {
            sec--;
            const m = Math.floor(sec/60), s = sec%60;
            countdownEl.textContent = `Code expires in ${m}:${s.toString().padStart(2,'0')}`;
            if (sec <= 0) {
                clearInterval(timer);
                // countdownEl.style.display = 'none';
                // resendLink.style.display = 'inline';
            }
        }, 1000);
    };


    // Unified form submission
    form.addEventListener('submit', e => {
        e.preventDefault();
        if (!hasInteracted || (<?php echo ! empty($settings->enable_bot_protection) ? 'true' : 'false'; ?> && !tokenFetched)) {
            msgEl.textContent = 'Please interact with the form and enable JavaScript.';
            return;
        }
        msgEl.textContent = '';
        const formData = new FormData(form);
        const submitButton = e.submitter || form.querySelector('#mnml-submit');
        submitButton.disabled = true;
        submitButton.value = 'Submitting...';

        const isLostPassword = formData.get('action') === 'lostpassword';
        const isResetPassword = formData.get('action') === 'resetpassword';
        const isInterimLogin = formData.get('interim-login') === '1';
        const is2FACode = formData.get('mnml2fac') && formData.get('mnml2fak');
        const endpoint = '<?php echo rest_url('mnml_login/v1/auth'); ?>';
        if (!isLostPassword && !isResetPassword && !isInterimLogin && !is2FACode && !formData.get('mnml2falog')) {
            msgEl.textContent = 'Please enter a Username or Email.';
            msgEl.style.display = 'block';
            submitButton.disabled = false;
            submitButton.value = '<?php echo strpos($settings->two_factor_auth, 'link') !== false ? 'Get Sign-on Link' : 'Log In'; ?>';
            return;
        }
        if (isResetPassword && (formData.get('pass1') !== formData.get('pass2'))) {
            msgEl.textContent = 'Passwords do not match.';
            msgEl.style.display = 'block';
            submitButton.disabled = false;
            submitButton.value = 'Reset Password';
            return;
        }

        fetch(endpoint, {
            method: 'POST',
            body: formData
        })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                if (data.redirect) {
                    window.location.href = data.redirect;
                } else if (data.twofa) {
                    form.classList.add('mnml-link-sent');
                    msgEl.textContent = data.message;
                    startCountdown();
                    if (data.token) {
                        form.querySelectorAll('#mnml2fak').forEach(el => el.value = data.token);
                    }
                    document.getElementById('mnml2fac')?.focus();
                    submitButton.disabled = false;
                    submitButton.value = 'Submit Code';
                } else if (isLostPassword) {
                    msgEl.textContent = data.message || 'Password reset email sent.';
                    submitButton.disabled = false;
                    submitButton.value = 'Get New Password';
                } else if (isResetPassword) {
                    msgEl.textContent = data.message || 'Password reset successful. Please log in.';
                    submitButton.disabled = false;
                    submitButton.value = 'Reset Password';
                } else if (isInterimLogin) {
                    msgEl.textContent = data.message || 'Login successful.';
                    submitButton.disabled = false;
                    submitButton.value = 'Log In';
                    document.body.classList.add('interim-login-success');
                    // window.parent.postMessage('mnml_interim_login_success', '*');// trying to trigger a load for this to hide asap but it doesnt work: https://github.com/WordPress/WordPress/blob/0514ff27d05f58ef674594e4e9ef662a66b5fd0a/wp-includes/js/wp-auth-check.js#L50
                <?php if ( strpos($settings->two_factor_auth, 'link') !== false ) : ?>
                } else if (data.message) {
                    form.classList.add('mnml-link-sent','mnml-no-2facode');
                    msgEl.textContent = data.message;
                <?php endif; ?>
                } else {
                    msgEl.textContent = 'Unexpected response. Please try again.';
                    submitButton.disabled = false;
                    submitButton.value = formData.get('action') === 'lostpassword' ? 'Get New Password' : isResetPassword ? 'Reset Password' : isInterimLogin ? 'Log In' : '<?php echo strpos($settings->two_factor_auth, 'link') !== false ? 'Get Sign-on Link' : 'Log In'; ?>';
                }
            } else {
                msgEl.textContent = data.message || 'An error occurred.';
                submitButton.disabled = false;
                if (data.message && ~data.message.indexOf('code') ) {
                    submitButton.value = 'Submit Code';
                } else {
                    submitButton.value = formData.get('action') === 'lostpassword' ? 'Get New Password' : isResetPassword ? 'Reset Password' : isInterimLogin ? 'Log In' : '<?php echo strpos($settings->two_factor_auth, 'link') !== false ? 'Get Sign-on Link' : 'Log In'; ?>';
                }
            }
        })
        .catch(() => {
            msgEl.textContent = 'Failed to connect to server.';
            submitButton.disabled = false;
            submitButton.value = formData.get('action') === 'lostpassword' ? 'Get New Password' : isResetPassword ? 'Reset Password' : isInterimLogin ? 'Log In' : '<?php echo strpos($settings->two_factor_auth, 'link') !== false ? 'Get Sign-on Link' : 'Log In'; ?>';
        });
    });
});
</script>
<?php
    return ob_get_clean();
}

// REST API endpoints
function register_api_endpoints() {
    register_rest_route('mnml_login/v1', '/get_token', [
        'methods'             => 'GET',
        'callback'            => __NAMESPACE__ . '\get_login_token',
        'permission_callback' => '__return_true',
    ]);
    register_rest_route('mnml_login/v1', '/auth', [
        'methods'             => 'POST',
        'callback'            => __NAMESPACE__ . '\auth_handler',
        'permission_callback' => '__return_true',
    ]);
    register_rest_route('mnml_login/v1', '/logout', [
        'methods'             => 'GET',
        'callback'            => __NAMESPACE__ . '\api_logout',
        'permission_callback' => '__return_true',
    ]);
    register_rest_route('mnml_login/v1', '/settings', [
        'methods'             => 'POST',
        'callback'            => __NAMESPACE__ . '\api_options',
        'permission_callback' => fn() => current_user_can('manage_options'),
    ]);
    register_rest_route('mnml_login/v1', '/simple_login', [
        'methods'             => 'POST',
        'callback'            => __NAMESPACE__ . '\trap_handler',
        'permission_callback' => '__return_true',
    ]);
}

function trap_handler($request) {
    $ip      = $_SERVER['HTTP_X_CLIENT_IP'] ?? $_SERVER['REMOTE_ADDR'];
    $ua      = $_SERVER['HTTP_USER_AGENT'] ?? 'none';
    $referer = $_SERVER['HTTP_REFERER'] ?? 'none';
    debug("MnmlLogin: Bot caught in honeypot form from $ip with UA $ua and referer $referer");
    http_response_code(403);
    die();
    return new \WP_Error('forbidden', 'Invalid request.', ['status' => 403]);
}

// Token endpoint
function get_login_token($request) {
    if (! session_id()) {
        session_start();
    }
    $secret                       = wp_salt('nonce');
    $token_data                   = random() . '|' . time();
    $encrypted_token              = base64_encode(openssl_encrypt($token_data, 'AES-256-CBC', $secret, 0, substr($secret, 0, 16)));
    $_SESSION['mnml_login_token'] = $encrypted_token;
    $_SESSION['form_load_time']   = time();
    debug("MnmlLogin: Token generated for IP: {$_SERVER['REMOTE_ADDR']}");
    return rest_ensure_response(['success' => true, 'data' => ['token' => $encrypted_token]]);
}

// Auth handler
function auth_handler($request) {
    $settings = (object) get_option('mnml_login', []);

    debug("MnmlLogin: Processing /auth POST");

    // Basic bot checks
    $user_agent   = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $bot_patterns = '/bot|crawler|spider|curl|wget|python-requests|httpclient|scrapy|go-http-client|libwww-perl|java\/|php\/|okhttp|axios/i';
    if (empty($user_agent) || ! isset($_SERVER['HTTP_ACCEPT']) || ! isset($_SERVER['HTTP_ACCEPT_LANGUAGE']) || preg_match($bot_patterns, $user_agent)) {
        debug("MnmlLogin: Bot detected: $user_agent");
        return new \WP_Error('forbidden', 'Access denied', ['status' => 403]);
    }

    // Token validation
    if (! empty($settings->enable_bot_protection)) {
        session_id() || session_start();
        $secret        = wp_salt('nonce');
        $posted_token  = $request->get_param('login_token') ?? '';
        $session_token = $_SESSION['mnml_login_token'] ?? '';
        if (! $posted_token || $posted_token !== $session_token) {
            debug("MnmlLogin: Invalid session token from IP: {$_SERVER['REMOTE_ADDR']}");
            return new \WP_Error('forbidden', 'Invalid session.', ['status' => 403]);
        }
        $decrypted = openssl_decrypt(base64_decode($posted_token), 'AES-256-CBC', $secret, 0, substr($secret, 0, 16));
        if (! $decrypted || strpos($decrypted, '|') === false) {
            debug("MnmlLogin: Invalid token decryption from IP: {$_SERVER['REMOTE_ADDR']}");
            return new \WP_Error('forbidden', 'Invalid token.', ['status' => 403]);
        }
        list($uuid, $timestamp) = explode('|', $decrypted);
        if (time() - $timestamp > 300) {
            debug("MnmlLogin: Session expired from IP: {$_SERVER['REMOTE_ADDR']}");
            return new \WP_Error('forbidden', 'Session expired.', ['status' => 403]);
        }
        if (! empty($settings->session_speed_check)) {
            if (time() - ($_SESSION['form_load_time'] ?? 0) < 2) {
                debug("MnmlLogin: Form submitted too quickly from IP: {$_SERVER['REMOTE_ADDR']}");
                return new \WP_Error('forbidden', 'Form submitted too quickly.', ['status' => 403]);
            }
        }
    }

    // Handle lost password
    if ($request->get_param('action') === 'lostpassword') {
        debug("MnmlLogin: Processing lost password");
        $user_data = retrieve_password($request->get_param('user_login'));
        if (is_wp_error($user_data)) {
            debug("MnmlLogin: Lost password error for " . $request->get_param('user_login') . ": " . $user_data->get_error_message());
            return new \WP_Error('bad_request', $user_data->get_error_message(), ['status' => 400]);
        }
        return rest_ensure_response(['success' => true, 'message' => 'Password reset email sent.']);
    }

    // Handle password reset
    if ($request->get_param('action') === 'resetpassword') {
        $rp_key = $request->get_param('rp_key');
        $rp_login = $request->get_param('rp_login');
        $pass1 = $request->get_param('pass1');
        if (!$rp_key || !$rp_login || !$pass1) {
            debug("MnmlLogin: Missing reset parameters from IP: {$_SERVER['REMOTE_ADDR']}");
            return new \WP_Error('bad_request', 'Invalid reset request.', ['status' => 400]);
        }
        $user = check_password_reset_key($rp_key, $rp_login);
        if (is_wp_error($user)) {
            debug("MnmlLogin: Invalid reset key or login: {$user->get_error_message()}");
            return new \WP_Error('bad_request', 'Invalid or expired reset link.', ['status' => 400]);
        }
        reset_password($user, $pass1);
        debug("MnmlLogin: Password reset successful for user: {$user->user_login}");
        return rest_ensure_response(['success' => true, 'message' => 'Password reset successful. Please log in.']);
    }

   // Authenticate 2FA code
    if (! empty($request->get_param('mnml2fac')) && ! empty($request->get_param('mnml2fak'))) {
        $code_key     = $request->get_param('mnml2fak');
        $posted_code  = trim( $request->get_param('mnml2fac') );
        $transient_key = "mnml_login_{$code_key}";

        if (! empty($settings->enable_bot_protection)) {
            session_id() || session_start();
            $session_token = $_SESSION['mnml_login_token'] ?? '';
            if ($code_key !== $session_token) {
                debug("MnmlLogin: Invalid code key from IP: {$_SERVER['REMOTE_ADDR']}");
                return new \WP_Error('bad_request', 'Invalid code key.', ['status' => 400]);
            }
        }

        $login_data = get_transient($transient_key);
        $login_data = (object) $login_data;

        if (empty($login_data->id) || empty($login_data->code)) {
            debug("MnmlLogin: No valid 2FA session for token: $code_key");
            return new \WP_Error('bad_request', 'Invalid or expired session.', ['status' => 400]);
        }

        // Wrong code
        if ($posted_code !== $login_data->code) {
            $login_data->attempts = ($login_data->attempts ?? 0) + 1;

            if ($login_data->attempts > 3) {
                delete_transient($transient_key);
                debug("MnmlLogin: 2FA failed 3 times – session deleted for token $code_key");
                return new \WP_Error('bad_request', 'Too many incorrect attempts. Please start again.', ['status' => 400]);
            }

            // Save updated attempt count
            set_transient($transient_key, $login_data, 300);

            $left = 4 - $login_data->attempts;
            return new \WP_Error('bad_request',
                "Incorrect code – $left " . _n('try', 'tries', $left) . ' left.',
                ['status' => 400]);
        }

        // Correct code → login
        delete_transient($transient_key);

        $user = get_user_by('id', $login_data->id);
        if (! $user) {
            debug("MnmlLogin: User not found for ID: {$login_data->id}");
            return new \WP_Error('bad_request', 'User not found.', ['status' => 400]);
        }

        if (empty($settings->no_login_alerts)) {
            $message = "New login from IP {$_SERVER['REMOTE_ADDR']}";
            wp_mail($user->user_email, $message, $message . "\n\nuser agent: {$_SERVER['HTTP_USER_AGENT']}");
        }

        wp_set_auth_cookie($user->ID, ! empty($request->get_param('rememberme')));
        do_action( 'wp_login', $user->user_login, $user );

        $response = ['success' => true];
        if ($request->get_param('interim-login') === '1') {
            $response['interim'] = true;
            $response['message'] = 'Login successful.';
        } else {
            $response['redirect'] = ! empty($login_data->redirect)
                ? wp_validate_redirect($login_data->redirect)
                : admin_url();
        }

        debug("MnmlLogin: 2FA login successful for user: {$user->user_login}");
        return rest_ensure_response($response);
    }

    // Handle User / Pass
    $creds = [
        'user_login'    => sanitize_user($request->get_param('mnml2falog') ?? ''),
        'user_password' => $request->get_param('pwd') ?? '',
        'remember'      => ! empty($request->get_param('rememberme')),
    ];
    if (empty($creds['user_login'])) {
        debug("MnmlLogin: Missing login for 2FA");
        return new \WP_Error('bad_request', 'Please enter Username or Email.', ['status' => 400]);
    }
    if (empty($creds['user_login']) || (empty($creds['user_password']) && ($settings->two_factor_auth === 'code' || $settings->two_factor_auth === 'none'))) {
        debug("MnmlLogin: Missing credentials: login={$creds['user_login']}");
        return new \WP_Error('bad_request', 'Please enter username/email and password.', ['status' => 400]);
    }
    // Find user
    $user = false;
    if (strpos($creds['user_login'], '@')) {
        $user = get_user_by('email', $creds['user_login']);
    } elseif (function_exists(__NAMESPACE__ . '\send_via_twilio')) {
        $maybe_tel = preg_replace('/\D/', '', $creds['user_login']);
        if (strlen($maybe_tel) > 8) {
            $user = apply_filters('mnml_login_get_user_by_tele', null, $maybe_tel);
            if ($user === null) {
                $meta_key = $settings->telephone_user_meta ?? 'mnml2fano';
                $users    = get_users(['meta_key' => $meta_key, 'meta_value' => $maybe_tel, 'number' => 2]);
                if (count($users) > 1) {
                    debug("MnmlLogin: Multiple accounts with phone: $maybe_tel");
                }
                $user = current($users);
            }
        }
    }
    if (! $user) {
        $user = get_user_by('login', $creds['user_login']);
    }
    if (! $user) {
        debug("MnmlLogin: No user found for login: {$creds['user_login']}");
        return new \WP_Error('bad_request', 'Invalid Username or Email.', ['status' => 400]);
    }

    // Authenticate for code, disabled 2FA, or interim login with grace period
    if ($settings->two_factor_auth === 'code' || $settings->two_factor_auth === 'none') {
        $user_auth = wp_authenticate($creds['user_login'], $creds['user_password']);
        if (is_wp_error($user_auth)) {
            debug("MnmlLogin: Authentication failed: " . $user_auth->get_error_message());
            return new \WP_Error('unauthorized', 'Invalid credentials.', ['status' => 401]);
        }
        debug( 'interim-login: ' . $request->get_param('interim-login') );
        if ($request->get_param('interim-login') === '1' && $settings->two_factor_auth === 'code') {
            debug('running interim');
            if (!empty($_COOKIE[ LOGGED_IN_COOKIE ])) {
                $cookie_elements = explode('|', $_COOKIE[ LOGGED_IN_COOKIE ]);
                if (count($cookie_elements) === 4) {
                    list($username, $expiration, $token, $hmac) = $cookie_elements;
                    $user = get_user_by('login', $username);
                    if ($user && $user->ID === $user_auth->ID) {
                        $sessions = get_user_meta($user->ID, 'session_tokens', true);
                        $cookie_hash = hash( 'sha256', $token );
                        debug(var_export($sessions,1));
                        debug($cookie_hash);
                        if (isset($sessions[$cookie_hash]) && $sessions[$cookie_hash]['expiration'] + HOUR_IN_SECONDS >= time() && ($ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '') === $sessions[$cookie_hash]['ip']) {
                            wp_set_auth_cookie($user->ID, $creds['remember']);
                            debug("MnmlLogin: Interim login successful (2FA skipped via session fallback) for user: {$user->user_login}");
                            return rest_ensure_response(['success' => true, 'interim' => true, 'message' => 'Login successful.']);
                        }
                    }
                }
            }
        }
    }

    // Send 2FA
    if ($settings->two_factor_auth !== 'none') {
        $login_data = (object) [
            'id' => $user->ID,
            'rm' => $creds['remember'],
            'ip' => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '',
        ];

        if (! empty($request->get_param('redirect_to'))) {
            $login_data->redirect = $request->get_param('redirect_to');
        }
        $code = false;
        $transient_token = false;
        if (strpos($settings->two_factor_auth, 'code') !== false) {
            $code = sprintf("%06s", random_int(0, 999999));
            $transient_token = ! empty($settings->enable_bot_protection) ? ($session_token ?? random()) : random();
        }

        if ($settings->two_factor_auth === 'code') {
            $sent = false;
            $return = 'email';
            if (function_exists(__NAMESPACE__ . '\send_via_twilio')) {
                $phone = apply_filters('mnml_login_get_tele_by_user', null, $user);
                if ($phone === null) {
                    $meta_key = $settings->telephone_user_meta ?? 'mnml2fano';
                    $phone = get_user_meta($user->ID, $meta_key, true);
                }
                if ($phone) {
                    $sent = send_via_twilio($phone, $code);
                    if ($sent) {
                        $sent = 'phone';
                        $return = 'phone';
                    } else {
                        if ( !empty( $settings->dont_fallback_to_email ) ) $dont_email = true;
                    }
                }
            }
            if (! $sent && empty( $dont_email ) ) {
                $email = $user->user_email;
                if (! $email) {
                    debug("MnmlLogin: No email for user: {$user->user_login}");
                    return new \WP_Error('bad_request', 'No email configured.', ['status' => 400]);
                }
                $subject = $settings->code_email_subject ?? 'Your security code is %code%';
                $subject = str_ireplace('%code%', $code, $subject);
                $body = $settings->code_email_body ?? 'Hello %name%, here is the security code you requested';
                $name = $user->first_name ?? $user->display_name ?? '';
                $body = str_ireplace([' %name%', '%name%'], ($name ? ' ' . $name : ''), $body);
                $body = add_markup_to_emails($body, $code);
                $sent = wp_mail($email, $subject, $body, 'Content-Type: text/html;');
                if ($sent) {
                    $sent = 'email';
                }
            }
            if ($sent) {
                $login_data->code = $code;
                $login_data->attempts = 1;
                set_transient("mnml_login_{$transient_token}", $login_data, 300);
                debug("MnmlLogin: 2FA code sent via $sent for user: {$user->user_login}");
            } else {
                debug("MnmlLogin: Failed to send 2FA code for user: {$user->user_login}");
                return new \WP_Error('server_error', 'Failed to send code.', ['status' => 500]);
            }
        }

        // Magic link (or both)
        if (strpos($settings->two_factor_auth, 'link') !== false) {
            do { $key = random(); } while (get_transient("mnml_login_{$key}"));// is it even worth checking for a duplicate?
            $link = get_home_url() . "?tfal={$key}";
            $sent = false;
            $return = 'email';
            if (function_exists(__NAMESPACE__ . '\send_via_twilio')) {
                $phone = apply_filters('mnml_login_get_tele_by_user', null, $user);
                if ($phone === null) {
                    $meta_key = $settings->telephone_user_meta ?? 'mnml2fano';
                    $phone = get_user_meta($user->ID, $meta_key, true);
                }
                if ($phone) {
                    $sent = send_via_twilio($phone, $code, $link);
                    if ($sent) {
                        $sent = 'phone';
                        $return = 'phone';
                    } else {
                        if ( !empty( $settings->dont_fallback_to_email ) ) $dont_email = true;
                    }
                }
            }
            if (! $sent && empty( $dont_email ) ) {
                $email = $user->user_email;
                $subject = $settings->link_email_subject ?? 'Your sign-in link';
                $body = $settings->link_email_body ?? 'Hello %name%, here is the sign-in link you requested';
                $name = $user->first_name ?? $user->display_name ?? '';
                $body = str_ireplace([' %name%', '%name%'], ($name ? ' ' . $name : ''), $body);
                $body = add_markup_to_emails($body, $code, $link);
                $sent = wp_mail($email, $subject, $body, 'Content-Type: text/html;');
                if ($sent) {
                    $sent = 'email';
                }
            }
            if ($sent) {
                set_transient("mnml_login_{$key}", $login_data, 300);
                debug("MnmlLogin: Magic link sent via $sent for user: {$user->user_email}");
                if (strpos($settings->two_factor_auth, 'code') !== false) {
                    $login_data->code = $code;
                    $login_data->attempts = 1;
                    set_transient("mnml_login_{$transient_token}", $login_data, 300);
                }
            } else {
                debug("MnmlLogin: Failed to send magic link for user: {$user->user_email}");
                return new \WP_Error('server_error', 'Failed to send link.', ['status' => 500]);
            }
        }

        return rest_ensure_response([
            'success' => true,
            'twofa' => $code ? true : false,
            'token' => $transient_token,
            'message' => "Check your $return for the " . (strpos($settings->two_factor_auth, 'link') !== false ? 'sign-in link' : 'security code'),
        ]);
    }

    // Non-2FA login
    wp_set_auth_cookie($user->ID, $creds['remember']);
    do_action( 'wp_login', $user->user_login, $user );
    $response = ['success' => true];
    if ($request->get_param('interim-login') === '1') {
        $response['interim'] = true;
        $response['message'] = 'Login successful.';
    } else {
        $response['redirect'] = ! empty($request->get_param('redirect_to')) ? wp_validate_redirect( $request->get_param('redirect_to') ) : admin_url();
    }
    debug("MnmlLogin: Login successful for user: {$user->user_login}");
    return rest_ensure_response($response);
}

// Magic link handler
function magic_link_handler($wp) {
    global $settings;
    if (! empty($_GET['tfal'])) {
        if (! empty($settings->enable_bot_protection)) {
            ! session_id() || session_start();
        }
        $login_data = get_transient("mnml_login_{$_GET['tfal']}");
        $login_data = (object) $login_data;
        if (empty($login_data->id)) {
            debug("MnmlLogin: Invalid or expired magic link: {$_GET['tfal']}");
            wp_die('Invalid or expired link.', 'Error', ['response' => 400]);
        }
        if (! empty($login_data->ip) && $login_data->ip !== ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'])) {
            debug("MnmlLogin: IP mismatch for magic link: stored={$login_data->ip}, current=" . ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR']) );
            // wp_die('IP mismatch.', 'Error', ['response' => 403]);
        }
        $user = get_user_by('id', $login_data->id);
        if (! $user) {
            debug("MnmlLogin: User not found for magic link ID: {$login_data->id}");
            wp_die('User not found.', 'Error', ['response' => 400]);
        }
        if (empty($settings->no_login_alerts)) {
            $message = "New login from IP {$_SERVER['REMOTE_ADDR']}";
            wp_mail($user->user_email, $message, $message . "\n\nuser agent: {$_SERVER['HTTP_USER_AGENT']}");
        }
        wp_set_auth_cookie($user->ID, ! empty($login_data->rm));
        do_action( 'wp_login', $user->user_login, $user );
        $redirect = ! empty($login_data->redirect) ? $login_data->redirect : admin_url();
        debug("MnmlLogin: Magic link login successful for user: {$user->user_login}");
        status_header(302);
        wp_safe_redirect($redirect);
        exit;
    }
}

// Logout endpoint
function api_logout($request) {
    if (! is_user_logged_in()) {
        return rest_ensure_response(['success' => true, 'message' => 'Already logged out.', 'redirect' => get_login_page_url()]);
    }

    $nonce = $request->get_param('_wpnonce');
    if (! $nonce || ! wp_verify_nonce($nonce, 'log-out')) {
        debug("MnmlLogin: Invalid logout nonce");
        return new \WP_Error('bad_request', 'Invalid nonce.', ['status' => 400]);
    }

    wp_logout();
    debug("MnmlLogin: User logged out successfully");
    $redirect = $request->get_param('redirect_to') ? esc_url_raw($request->get_param('redirect_to')) : get_login_page_url();
    return rest_ensure_response(['success' => true, 'message' => 'Logged out.', 'redirect' => $redirect]);
}

// Logout handler
function logout_handler($wp) {
    if (! empty($_GET['action']) && $_GET['action'] === 'logout' && ! empty($_GET['_wpnonce'])) {
        if (! is_user_logged_in()) {
            wp_safe_redirect(get_login_page_url());
            exit;
        }

        $nonce = $_GET['_wpnonce'];
        if (! wp_verify_nonce($nonce, 'log-out')) {
            debug("MnmlLogin: Invalid logout nonce in URL");
            wp_die('Invalid nonce.', 'Error', ['response' => 400]);
        }

        wp_logout();
        debug("MnmlLogin: User logged out successfully via URL");
        $redirect = ! empty($_GET['redirect_to']) ? esc_url_raw($_GET['redirect_to']) : get_login_page_url();
        wp_safe_redirect($redirect);
        exit;
    }
}

// Custom logout URL
function custom_logout_url($logout_url, $redirect) {
    $args = ['action' => 'logout', '_wpnonce' => wp_create_nonce('log-out')];
    if ($redirect) {
        $args['redirect_to'] = urlencode($redirect);
    }
    return add_query_arg($args, get_login_page_url());
}

// Customize login URL for interim logins
function custom_login_url($login_url, $redirect, $force_reauth) {
    return get_login_page_url();
}

function api_options($request) {
    $data = $request->get_params();
    foreach ($data as $k => $v) {
        update_option($k, array_filter($v, 'strlen'));
    }
    return 'Saved';
}


add_filter('determine_current_user', __NAMESPACE__ . '\extend_auth_cookie_2', 30 );
// modified from wp_validate_auth_cookie()
function extend_auth_cookie_2( $user_id ) {

    if ( $user_id || empty( $_COOKIE[ LOGGED_IN_COOKIE ] ) || ! did_action('auth_cookie_expired') ) {
        return $user_id;
    }

    $settings = (object) get_option('mnml_login', []);

    if (empty($settings->session_extend_timeout) || empty($settings->session_extend_max_inactive) ) {
        return false;
    }
    
    $cookie_elements = wp_parse_auth_cookie( $_COOKIE[ LOGGED_IN_COOKIE ], 'logged_in' );

    $scheme     = $cookie_elements['scheme'];
    $username   = $cookie_elements['username'];
    $hmac       = $cookie_elements['hmac'];
    $token      = $cookie_elements['token'];
    $expiration = $cookie_elements['expiration'];

    $expired = (int) $expiration;

    $expired += (int) $settings->session_extend_max_inactive;

    if ( $expired < time() ) {
        return false;
    }

    $user = get_user_by( 'login', $username );
    if ( ! $user ) {
        do_action( 'auth_cookie_bad_username', $cookie_elements );
        return false;
    }

    if ( str_starts_with( $user->user_pass, '$P$' ) || str_starts_with( $user->user_pass, '$2y$' ) ) {
        // Retain previous behaviour of phpass or vanilla bcrypt hashed passwords.
        $pass_frag = substr( $user->user_pass, 8, 4 );
    } else {
        // Otherwise, use a substring from the end of the hash to avoid dealing with potentially long hash prefixes.
        $pass_frag = substr( $user->user_pass, -4 );
    }

    $key = wp_hash( $username . '|' . $pass_frag . '|' . $expiration . '|' . $token, $scheme );

    $hash = hash_hmac( 'sha256', $username . '|' . $expiration . '|' . $token, $key );

    if ( ! hash_equals( $hash, $hmac ) ) {
        do_action( 'auth_cookie_bad_hash', $cookie_elements );
        return false;
    }

    $sessions = get_user_meta($user->ID, 'session_tokens', true);
    $verifier = hash( 'sha256', $cookie_elements['token'] );
    if (!isset($sessions[$verifier])) {
        debug("MnmlLogin: Invalid session for session extension: user={$user->ID}");
        do_action( 'auth_cookie_bad_session_token', $cookie_elements );
        return false;
    }

    // Extend session
    $timeout = (int) $settings->session_extend_timeout;
    $sessions[$verifier]['expiration'] = time() + $timeout;
    update_user_meta($user->ID, 'session_tokens', $sessions);
    wp_set_auth_cookie($user->ID, !empty($sessions[$verifier]['remember']), '', $token);// this uses the standard expires time still...
    debug("MnmlLogin: Session extended on auth cookie expiration for user ID: {$user->ID}");

    do_action( 'auth_cookie_valid', $cookie_elements, $user );

    return $user->ID;
}


// Extend session when auth cookie expires
function extend_auth_cookie($cookie_elements) {
    debug('auth_cookie_expired');
    $settings = (object) get_option('mnml_login', []);
    if (empty($settings->session_extend_timeout) || empty($cookie_elements['username'])) {
        return false;
    }

    $user = get_user_by('login', $cookie_elements['username']);
    if (!$user) {
        debug("MnmlLogin: User not found for expired cookie: {$cookie_elements['username']}");
        return false;
    }
    $user_id = $user->ID;

    $sessions = get_user_meta($user_id, 'session_tokens', true);
    $cookie_hash = hash( 'sha256', $cookie_elements['token'] );
    // debug(var_export($sessions,1));
    // debug(var_export($cookie_hash,1));
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '';
    if (!isset($sessions[$cookie_hash]) || $ip !== $sessions[$cookie_hash]['ip']) {
        debug("MnmlLogin: Invalid session or IP mismatch for session extension: user=$user_id, IP=$ip");
        return false;
    }

    // Extend session
    $timeout = (int) $settings->session_extend_timeout;
    $sessions[$cookie_hash]['expiration'] = time() + $timeout;
    update_user_meta($user_id, 'session_tokens', $sessions);
    wp_set_auth_cookie($user_id, !empty($sessions[$cookie_hash]['remember']), '', $cookie_elements['token']);
    debug("MnmlLogin: Session extended on auth cookie expiration for user ID: $user_id");
    $new_cookie = wp_generate_auth_cookie($user_id, $sessions[$cookie_hash]['expiration'], 'logged_in', $cookie_elements['token']);
    $_COOKIE[LOGGED_IN_COOKIE] = $new_cookie;
}
// add_filter('auth_cookie_expired', __NAMESPACE__ . '\extend_auth_cookie');

// Extend session on wp-admin page load with activity tracking
function extend_session_page_load() {
    $settings = (object) get_option('mnml_login', []);
    if (!is_user_logged_in() || empty($settings->session_extend_timeout) || empty($settings->session_extend_threshold)) {
        return;
    }

    $user_id = get_current_user_id();
    update_user_meta($user_id, 'mnml_last_active', time()); // Track activity
    $last_active = (int) get_user_meta($user_id, 'mnml_last_active', true);
    if ($last_active < time() - ($settings->session_extend_max_inactive ?? 172800)) {
        debug("MnmlLogin: Skipping session extension due to inactivity for user ID: $user_id");
        return;
    }

    $cookie = false;
    foreach ($_COOKIE as $name => $value) {
        if (strpos($name, 'wordpress_logged_in_') === 0) {
            $cookie = $value;
            break;
        }
    }
    if (!$cookie) {
        debug("MnmlLogin: No auth cookie for session extension");
        return;
    }

    $cookie_elements = explode('|', $cookie);
    if (count($cookie_elements) !== 4) {
        debug("MnmlLogin: Invalid cookie format for session extension");
        return;
    }
    list($username, $expiration, $token, $hmac) = $cookie_elements;
    if ($expiration > time() + $settings->session_extend_threshold) {
        return; // Cookie not close to expiring
    }

    $sessions = get_user_meta($user_id, 'session_tokens', true);
    $cookie_hash = wp_hash($cookie);
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '';
    if (!isset($sessions[$cookie_hash]) || $ip !== $sessions[$cookie_hash]['ip']) {
        debug("MnmlLogin: Invalid session or IP mismatch for session extension: user=$user_id, IP=$ip");
        return;
    }

    // Extend session
    $timeout = (int) $settings->session_extend_timeout;
    $sessions[$cookie_hash]['expiration'] = time() + $timeout;
    update_user_meta($user_id, 'session_tokens', $sessions);
    wp_set_auth_cookie($user_id, !empty($sessions[$cookie_hash]['remember']));
    debug("MnmlLogin: Session extended on page load for user ID: $user_id");
}
// add_action('admin_init', __NAMESPACE__ . '\extend_session_page_load');

// Block wp-login.php
function block_wp_login() {
    if (false !== strpos($_SERVER['REQUEST_URI'], 'wp-login.php')) {
        $settings = (object) get_option('mnml_login', []);
        if ( empty( $settings->block_wp_login ) ) return;
        status_header(403);
        die();
    }
    if ((strpos($_SERVER['REQUEST_URI'], '/wp-json/mnml_login/v1/') !== false) && 'POST' === $_SERVER['REQUEST_METHOD']) {
        $expected_referer    = parse_url(home_url(), PHP_URL_HOST);
        $referer             = $_SERVER['HTTP_REFERER'] ?? 'none';
        $ip                  = $_SERVER['HTTP_X_CLIENT_IP'] ?? $_SERVER['REMOTE_ADDR'];
        $ua                  = $_SERVER['HTTP_USER_AGENT'] ?? 'none';
        $allow_empty_referer = preg_match('/Firefox|TorBrowser|Mobile.*Safari/i', $ua);
        if ((empty($referer) || $referer === 'none' || strpos(parse_url($referer, PHP_URL_HOST), $expected_referer) === false) && ! $allow_empty_referer) {
            debug("MnmlLogin: Spam login attempt to {$_SERVER['REQUEST_URI']} from $ip with UA $ua and referer $referer");
            status_header(403);
            die();
        } else {
            debug("MnmlLogin: Login attempt to {$_SERVER['REQUEST_URI']} from $ip with UA $ua and referer $referer");
        }
    }
}

// Settings page
function admin_menu() {
    add_submenu_page('options-general.php', 'Mnml Login', 'Mnml Login', 'edit_users', 'mnml_login', __NAMESPACE__ . '\settings_page');
}

function add_settings_link($links, $file) {
    if ($file === plugin_basename(__FILE__) && current_user_can('manage_options')) {
        $url     = admin_url('options-general.php?page=mnml_login');
        $links[] = sprintf('<a href="%s">Settings</a>', $url);
    }
    return $links;
}

function settings_page() {
    $fields = array_fill_keys([
        'two_factor_auth',
        'no_login_alerts',
        'block_wp_login',
        'private_site',
        'use_custom_homepage',
        'allow_api_discovery',
        'enable_bot_protection',
        'session_extend_timeout',
        'session_extend_max_inactive',
        'code_settings',
        'code_email_subject',
        'code_email_body',
        'code_sms_message',
        'code_settings_end',
        'link_settings',
        'link_email_subject',
        'link_email_body',
        'link_button_text',
        'link_button_color',
        'link_sms_message',
        'link_settings_end',
        'twilio_account_sid',
        'twilio_api_sid',
        'twilio_api_secret',
        'twilio_messaging_service_sid',
        'twilio_from',
        'dont_fallback_to_email',
        'telephone_user_meta',
    ], ['type' => 'text']);

    $fields['block_wp_login']                              = ['type' => 'checkbox', 'desc' => 'Block the standard login form. Recommended once you have this plugin’s custom login working.', 'label' => 'Block wp-login.php'];
    $fields['enable_bot_protection']                       = ['type' => 'checkbox', 'desc' => 'Requires user interaction and JavaScript to submit the form.'];
    $fields['code_settings']                               = ['type' => 'section', 'show' => ['two_factor_auth' => 'code']];
    $fields['private_site']                                = ['type' => 'checkbox', 'desc' => 'Restrict site to logged-in users and redirect all URLs to homepage with login form'];
    $fields['allow_api_discovery']                         = ['type' => 'checkbox', 'show' => [ 'private_site' => 'any', 'use_custom_homepage' => 'empty' ], 'desc' => 'Include the WP REST API discovery <link> in the <head> of the login page.  This will make your site more obviously a WordPress site, but you might need it for certain 3rd-party integrations'];
    $fields['use_custom_homepage']                         = ['type' => 'checkbox', 'show' => 'private_site', 'desc' => 'Use your themes homepage for the login page. You must add [mnml_login] manually to homepage content, and hide the main content with a conditional shortcode.  You can wrap content in shortcodes [mnml_logged_in] and [mnml_logged_out] or any third-party method.  Your content might look like this:  <code>[mnml_logged_out]Please log in [mnml_login][/mnml_logged_out] [mnml_logged_in]This is the main content for logged in users only.[/mnml_logged_in]</code>'];
    $fields['code_settings_end']                           = ['type' => 'section_end'];
    $fields['link_settings']                               = ['type' => 'section', 'show' => ['two_factor_auth' => ['link', 'link + code']]];
    $fields['link_settings_end']                           = ['type' => 'section_end'];
    $fields['two_factor_auth']                             = ['type' => 'radio', 'options' => ['none', 'code', 'link', 'link + code']];
    $fields['session_extend_timeout']                      = ['type' => 'number', 'desc' => 'Seconds to extend session on cookie expiration (0 to disable, default 172800)', 'placeholder' => '172800'];
    $fields['session_extend_max_inactive']                 = ['type' => 'number', 'desc' => 'Max seconds of inactivity before skipping session extension (default 172800)', 'placeholder' => '172800'];
    $fields['code_email_body']['type']                     = 'textarea';
    $fields['link_email_body']['type']                     = 'textarea';
    $fields['code_sms_message']['type']                    = 'textarea';
    $fields['link_sms_message']['type']                    = 'textarea';
    $fields['code_email_body']['placeholder']              = 'Hello %name%, here is the security code you requested';
    $fields['code_email_subject']['placeholder']           = 'Your security code is %code%';
    $fields['code_sms_message']['placeholder']             = 'Your security code is %code%';
    $fields['link_email_subject']['placeholder']           = 'Your sign-in link';
    $fields['link_email_body']['placeholder']              = 'Hello %name%, here is the sign-in link you requested';
    $fields['link_button_text']['placeholder']             = 'Sign In';
    $fields['link_button_color']['placeholder']            = '#777777';
    $fields['link_sms_message']['placeholder']             = 'Click to sign in: %link%';
    $fields['no_login_alerts']                             = ['type' => 'checkbox', 'desc' => 'Disable new login alert emails'];
    $fields['twilio_account_sid']['before']                = '<h3>Twilio settings for SMS codes instead of email</h3>';
    $fields['twilio_account_sid']['placeholder']           = 'AC...';
    $fields['twilio_messaging_service_sid']['placeholder'] = 'MG...';
    $fields['dont_fallback_to_email']                      = ['type' => 'checkbox', 'desc' => 'If a user has a phone number set, and the sms fail to send, do not fall back to sending email.'];

    $options  = ['mnml_login' => $fields];
    $endpoint = rest_url('mnml_login/v1/settings');
    $title    = 'Mnml Login Settings';
    require __DIR__ . '/settings-page.php';
}

// Email markup
function add_markup_to_emails($message, $code = '', $link = '') {
    global $settings;
    if (strpos($message, '<p') === false && strpos($message, '<br') === false) {
        $message = str_replace("\n", '<br>', $message);
    }
    $concern = 'If you did not just try to login, someone knows or has guessed your ';
    $concern .= $link ? 'login, but they cannot login without this link.' : 'password, but they cannot login without this code.';
    ob_start();
?>
<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
<meta charset="UTF-8">
<meta content="width=device-width, initial-scale=1" name="viewport">
<meta name="x-apple-disable-message-reformatting">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<style type="text/css">
@media only screen and (max-width: 600px) {
    table { width: 100% !important; }
}
</style>
</head>
<body style="width:100%;-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;font-family:sans-serif;line-height:1.5;padding:0;margin:0;background-color:#F6F6F6;">
<table style="border-collapse:collapse;border-spacing:0px;width:100%;height:100%;background-color:#F6F6F6" cellspacing="0" cellpadding="0">
<tr style="border-collapse:collapse;">
    <td style="padding:24px;" align="center">
        <table style="background-color:#ffffff;width:600px;" cellspacing="0" cellpadding="0">
            <tr style="border-collapse:collapse;">
                <td style="padding:24px;text-align:center;font-size:16px">
                    <?php
                        echo $message;
                            if ($link) {
                                $button_text  = $settings->link_button_text ?? 'Sign In';
                                $button_color = $settings->link_button_color ?? '#777';
                                echo "<p style='margin:36px;'><a href='{$link}' style='background:{$button_color};padding:12px 16px;color:#fff;text-decoration:none;font-weight:700;'>{$button_text}</a></p>";
                                if ($code) {
                                    echo '<p>or enter this code on the open login page:</p>';
                                }
                            }
                            if ($code) {
                                echo "<p style='font-size:36px;letter-spacing:6px;margin:24px;'>{$code}</p>";
                            }
                            echo "<p style='font-size:13px;'>{$concern}</p>";
                        ?>
                </td>
            </tr>
        </table>
    </td>
</tr>
<tr style="border-collapse:collapse;">
    <td style="text-align:center;padding:0 0 48px;">
        <p><a href="<?php echo get_option('home'); ?>"><?php echo get_option('blogname'); ?></a></p>
    </td>
</tr>
</table>
</body>
</html>
<?php
    return ob_get_clean();
}

// Customize lost password email
function customize_lost_password_email($message, $key, $user_login, $user_data) {
    $settings = (object) get_option('mnml_login', []);
    $reset_url = add_query_arg(['action' => 'rp', 'key' => $key, 'login' => rawurlencode($user_login)], get_login_page_url());
    $subject = $settings->code_email_subject ?? 'Reset Your Password';
    $body = $settings->code_email_body ?? 'Hello %name%, here is the link to reset your password';
    $name = $user_data->first_name ?? $user_data->display_name ?? '';
    $body = str_ireplace([' %name%', '%name%'], ($name ? ' ' . $name : ''), $body);
    $body = add_markup_to_emails($body, '', $reset_url);
    return $body;
}
add_filter('retrieve_password_message', __NAMESPACE__ . '\customize_lost_password_email', 10, 4);

/**
 * Generate random strings
 */
function random($len = 16, $prefix = '') {
    $len = $len / 2;
    $chars = array_merge(range('0', '9'), range('A', 'Z'), range('a', 'z'));
    for ($i = 0; $i < $len; $i++) $prefix .= $chars[mt_rand(0, count($chars) - 1)];
    return $prefix . bin2hex(random_bytes($len / 2));
}


function debug( $var, $note = '', $force = false ) {

    if ( ( ! defined('WP_DEBUG') || ! WP_DEBUG ) && ! $force ) {
        return;
    }
    $log_file = __DIR__ . "/mnml-login.log";
    $timestamp = date('Y-m-d H:i:s T');
    $note_part = $note ? "***{$note}*** " : '';
    $value = is_string($var) ? $var : var_export($var, true);

    $message = "[{$timestamp}] {$note_part}{$value}" . PHP_EOL;

    error_log( $message, 3, $log_file );
}