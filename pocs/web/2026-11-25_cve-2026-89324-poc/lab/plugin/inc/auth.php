<?php 
/**
 * Social network authentication
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit; // Direct access not allowed.
}
define( 'BASEL_PT_3D', plugin_dir_path( __DIR__ ) );

class BASEL_Auth {

    private $current_url;

    private $available_networks = array( 'facebook', 'vkontakte', 'google' );

	public function __construct() {
        if (function_exists('basel_http') && ( isset( $_SERVER['HTTP_HOST'] ) && isset( $_SERVER['REQUEST_URI'] ) )) {
            $this->current_url = basel_http() . '://' . "{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}";
        }
    	add_action('init', array( $this, 'auth' ), 20);
    	add_action('init', array( $this, 'process_auth_callback' ), 30);
		add_action( 'init', array( $this, 'remove_captcha' ), -10 );
	}

	function remove_captcha() {
		add_filter(
			'anr_get_option',
			function ( $option_values, $option, $default, $is_default ) {
				if ( is_array( $option_values ) && $option === 'enabled_forms' ) {
					foreach ( $option_values as $key => $value ) {
						if ( ( $value === 'registration' || $value === 'login' ) && isset( $_GET['opauth'] ) ) {
							unset( $option_values[ $key ] );
						}
					}
				}
				return $option_values;
			},
			10000000,
			4
		);
	}

    public function auth() {
        if( empty( $_GET['social_auth'] ) && empty( $_GET['code'] ) ) {
            return;
        }

        $network = ( empty( $_GET['social_auth'] ) ) ? $this->get_current_callback_network() : sanitize_key( $_GET['social_auth'] );

        if( ! in_array( $network, $this->available_networks) ) return;

        new Opauth( $this->get_config( $network ) );
    }

    public function process_auth_callback() {
        if ( isset( $_GET['error_reason'] ) && $_GET['error_reason'] == 'user_denied' ) {
            wp_redirect( $this->get_account_url() );
            exit;
        }
        if( empty( $_GET['opauth'] ) || is_user_logged_in() ) return;

		$response = json_decode( base64_decode( $_GET['opauth'] ), true );

		if ( empty( $response['auth'] ) || empty( $response['timestamp'] ) || empty( $response['signature'] ) || empty( $response['auth']['provider'] ) || empty( $response['auth']['uid'] ) ) {
			wp_redirect( $this->get_account_url() );
			exit;
		}

		$opauth = new Opauth( $this->get_config( strtolower( $response['auth']['provider'] ) ), false );

		if ( ! $opauth->validate( sha1( print_r( $response['auth'], true) ), $response['timestamp'], $response['signature'] ) ) {
			wp_redirect( $this->get_account_url() );
			exit;
		}

        switch ( $response['auth']['provider'] ) {
            case 'Facebook':
                if( empty( $response['auth']['info'] ) ) {
                    wc_add_notice( __( 'Can\'t login with Facebook. Please, try again later.', 'basel' ), 'error' );
                    return;
                }

                $email = isset( $response['auth']['info']['email'] ) ? $response['auth']['info']['email'] : '';

                if( empty( $email ) ) {
                    wc_add_notice( __( 'Facebook doesn\'t provide your email. Try to register manually.', 'basel' ), 'error' );
                    return;
                }

                $this->register_or_login( $email );
            break;
            case 'Google':

                if( empty( $response['auth']['info'] ) ) {
                    wc_add_notice( __( 'Can\'t login with Google. Please, try again later.', 'basel' ), 'error' );
                    return;
                }

                $email = isset( $response['auth']['info']['email'] ) ? $response['auth']['info']['email'] : '';

                if( empty( $email ) ) {
                    wc_add_notice( __( 'Google doesn\'t provide your email. Try to register manually.', 'basel' ), 'error' );
                    return;
                }

                $this->register_or_login( $email );
            break;
            case 'VKontakte':

                if( empty( $response['auth']['info'] ) ) {
                    wc_add_notice( __( 'Can\'t login with VKontakte. Please, try again later.', 'basel' ), 'error' );
                    return;
                }

                $email = isset( $response['auth']['info']['email'] ) ? $response['auth']['info']['email'] : '';

                if( empty( $email ) ) {
                    wc_add_notice( __( 'VK doesn\'t provide your email. Try to register manually.', 'basel' ), 'error' );
                    return;
                }

                $this->register_or_login( $email );
            break;
            
            default:
            break;
        }
    }

    public function register_or_login( $email ) {

		add_filter('pre_option_woocommerce_registration_generate_username', array( $this, 'return_yes' ), 10);
		add_filter( 'dokan_register_nonce_check', '__return_false' );

        $password = wp_generate_password();
        $customer = wc_create_new_customer( $email, '', $password);

        $user = get_user_by('email', $email);

        if( is_wp_error( $customer ) ) {
            if( isset( $customer->errors['registration-error-email-exists'] ) ) {
                wc_set_customer_auth_cookie( $user->ID );
            }
        } else {
            wc_set_customer_auth_cookie( $customer );
        }

        wc_add_notice( sprintf( __( 'You are now logged in as <strong>%s</strong>', 'basel' ), $user->display_name ) );

        remove_filter('pre_option_woocommerce_registration_generate_username', array( $this, 'return_yes' ), 10);
    }

    public function get_current_callback_network() {
        $account_url = $this->get_account_url();

        foreach ($this->available_networks as $network) {
            if( strstr( $this->current_url, trailingslashit( $account_url ) . $network ) ) {
                return $network;
            }
        }

        return false;
    }

	public function get_account_url() {
		if (function_exists('wc_get_page_permalink')) {
			return untrailingslashit( wc_get_page_permalink('myaccount') );
		} else { 
			return '';
		}
	}

    public function return_yes() {
        return 'yes';
    }

	private function get_config( $network ) {
		$account_url   = $this->get_account_url();
		$security_salt = apply_filters('basel_opauth_salt', '2NlBUibcszrVtNmDnxqDbwCOpLWq91eatIz6O1O');

		if ( defined( SECURE_AUTH_SALT ) ) {
			$security_salt = SECURE_AUTH_SALT;
		}

		$callback_param = 'int_callback';
		switch ( $network ) {
			case 'google':
				$app_id         = basel_get_opt('goo_app_id');
				$app_secret     = basel_get_opt('goo_app_secret');

				if( empty( $app_secret ) || empty( $app_id ) ) return;

				$strategy       = array(
					'Google' => array(
						'client_id' => $app_id,
						'client_secret' => $app_secret,
						#'scope' => 'email'
					),
				);

				$callback_param = 'oauth2callback';

				break;

			case 'vkontakte':
				$app_id         = basel_get_opt('vk_app_id');
				$app_secret     = basel_get_opt('vk_app_secret');

				if( empty( $app_secret ) || empty( $app_id ) ) return;

				$strategy       = array(
					'VKontakte' => array(
						'app_id' => $app_id,
						'app_secret' => $app_secret,
						'scope' => 'email'
					),
				);
				break;

			default:
				$app_id     = basel_get_opt('fb_app_id');
				$app_secret = basel_get_opt('fb_app_secret');

				if( empty( $app_secret ) || empty( $app_id ) ) return;

				$strategy       = array(
					'Facebook' => array(
						'app_id'     => $app_id,
						'app_secret' => $app_secret,
						'scope'      => 'email'
					),
				);
				break;
		}

		$config = array(
			'security_salt'      => $security_salt,
			'host'               => $account_url,
			'path'               => '/',
			'callback_url'       => $account_url,
			'callback_transport' => 'get',
			'strategy_dir'       => BASEL_PT_3D . '/vendor/opauth/',
			'Strategy'           => $strategy,
		);

		if( empty( $_GET['code'] ) ) {
			$config['request_uri'] = '/' . $network;
		} else {
			$config['request_uri'] = '/' . $network . '/' . $callback_param . '?code=' . $_GET['code'];
		}

		return $config;
	}
}
