<?php namespace Pyrello\OAuth2Xml;

use Exception;
use Input;
use League\OAuth2\Server\Authorization;
use League\OAuth2\Server\Exception\ClientException;
use LucaDegasperi\OAuth2Server\Proxies\AuthorizationServerProxy as ServerProxy;
use Response;

class AuthorizationServerProxy extends ServerProxy
{
    /**
     * Type of request/response
     *
     * @var string
     */
    protected $reponseType = 'json';

    public function __construct(Authorization $authServer)
    {
        \Log::debug('constructing AuthServer...');
        parent::__construct($authServer);
        if (null !== Input::get('response_type')) {
            $this->reponseType = Input::get('response_type');
        }
    }

    /**
     * Perform the access token flow
     *
     * @return Response the appropriate response object
     */
    public function performAccessTokenFlow()
    {
        $status = 200;
        $headers = [];

        try {

            // Get user input
            $input = Input::all();

            // Tell the auth server to issue an access token
            $response = $this->authServer->issueAccessToken($input);

        } catch (ClientException $e) {

            // Throw an exception because there was a problem with the client's request
            $response = array(
                'error' =>  $this->authServer->getExceptionType($e->getCode()),
                'error_description' => $e->getMessage()
            );

            // make this better in order to return the correct headers via the response object
            $error = $this->authServer->getExceptionType($e->getCode());
            $status = self::$exceptionHttpStatusCodes[$error];
            $headers = $this->authServer->getExceptionHttpHeaders($error);

        } catch (Exception $e) {

            // Throw an error when a non-library specific exception has been thrown
            $response = array(
                'error' =>  'undefined_error',
                'error_description' => $e->getMessage()
            );

            $status = 500;
        }

        if ($this->reponseType === 'xml') {
            Response::xml($response, $status, $headers);
        }

        return Response::json($response, $status, $headers);
    }
} 