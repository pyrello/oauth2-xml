<?php namespace Pyrello\OAuth2Xml;

use Illuminate\Support\ServiceProvider;
use LucaDegasperi\OAuth2Server\OAuth2ServerServiceProvider;

class OAuth2XmlServiceProvider extends OAuth2ServerServiceProvider
{

    /**
     * Indicates if loading of the provider is deferred.
     *
     * @var bool
     */
    protected $defer = false;

    /**
     * Bootstrap the application events.
     *
     * @return void
     */
    public function boot()
    {
        $this->package('pyrello/oauth2-xml', 'lucadegasperi/oauth2-server-laravel');
    }

    public function register()
    {
        $app = $this->app;

        $app['pearson.authorization-server'] = $app->share(function ($app) {

            $server = $app->make('League\OAuth2\Server\Authorization');

            $config = $app['config']->get('pyrello/oauth2-xml::oauth2');

            // add the supported grant types to the authorization server
            foreach ($config['grant_types'] as $grantKey => $grantValue) {

                $server->addGrantType(new $grantValue['class']($server));
                $server->getGrantType($grantKey)->setAccessTokenTTL($grantValue['access_token_ttl']);

                if (array_key_exists('callback', $grantValue)) {
                    $server->getGrantType($grantKey)->setVerifyCredentialsCallback($grantValue['callback']);
                }
                if (array_key_exists('auth_token_ttl', $grantValue)) {
                    $server->getGrantType($grantKey)->setAuthTokenTTL($grantValue['auth_token_ttl']);
                }
                if (array_key_exists('refresh_token_ttl', $grantValue)) {
                    $server->getGrantType($grantKey)->setRefreshTokenTTL($grantValue['refresh_token_ttl']);
                }
                if (array_key_exists('rotate_refresh_tokens', $grantValue)) {
                    $server->getGrantType($grantKey)->rotateRefreshTokens($grantValue['rotate_refresh_tokens']);
                }
            }

            $server->requireStateParam($config['state_param']);

            $server->requireScopeParam($config['scope_param']);

            $server->setScopeDelimeter($config['scope_delimiter']);

            $server->setDefaultScope($config['default_scope']);

            $server->setAccessTokenTTL($config['access_token_ttl']);

            return new AuthorizationServerProxy($server);

        });
    }

}
