<?php

namespace MaximeRainville\Impersonate;

use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\RequestHandler;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Authenticator as SSAuthenticator;
use SilverStripe\Security\IdentityStore;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\Form;
use SilverStripe\Forms\HiddenField;
use SilverStripe\Forms\FormAction;
use PageController;

/**
 * Handle login requests from MaximeRainville\Auth0\Authenticator.
 *
 * @internal Mostly copied from the regular LoginHandler. Unfortunately, the regular login handler is tightly coupled
 * with the MemberLoginForm, which makes our work a bit more difficult here.
 */
class LoginHandler extends RequestHandler
{
    /**
     * @var SSAuthenticator
     */
    protected $authenticator;

    /**
     * @var array
     * @config
     */
    private static $url_handlers = [
        '' => 'login',
    ];

    /**
     * @var array
     * @config
     */
    private static $allowed_actions = [
        'login',
        'Form'
    ];

    /**
     * @var string Called link on this handler
     */
    private $link;

    /**
     * @param string $link The URL to recreate this request handler
     * @param SSAuthenticator $authenticator The authenticator to use
     */
    public function __construct($link, SSAuthenticator $authenticator)
    {
        $this->link = $link;
        $this->authenticator = $authenticator;
        parent::__construct();
    }

    /**
     * Return a link to this request handler.
     * The link returned is supplied in the constructor
     * @param null|string $action
     * @return string
     */
    public function link($action = null)
    {
        if ($action) {
            return Controller::join_links($this->link, $action);
        }

        return $this->link;
    }

    /**
     * URL handler for the log-in screen
     *
     * @return array
     */
    public function login()
    {
        return ['Form' => $this->Form()];
    }

    /**
     * Display a login form.
     * @return Form
     */
    public function Form()
    {
        return LoginForm::create($this, 'Form');
    }

    /**
     * Do the actual login action that will redirect the user to Auth0 for authentication.
     * @return void
     */
    public function doLogin($data)
    {
        Security::setCurrentUser(null);

        // Successful login
        if ($member = Member::get()->byID($data['MemberID'])) {
            $identityStore = Injector::inst()->get(IdentityStore::class);
            $identityStore->logIn($member, false, $this->getRequest());
            return $this->redirectAfterSuccessfulLogin();
        }

        $this->extend('failedLogin');

        $this->httpError(
            401,
            'Could not log you in.'
        );
    }

    /**
     * Login in the user and figure out where to redirect the browser.
     *
     * The $data has this format
     * array(
     *   'AuthenticationMethod' => 'MemberAuthenticator',
     *   'Email' => 'sam@silverstripe.com',
     *   'Password' => '1nitialPassword',
     *   'BackURL' => 'test/link',
     *   [Optional: 'Remember' => 1 ]
     * )
     *
     * @return HTTPResponse
     */
    protected function redirectAfterSuccessfulLogin()
    {
        $member = Security::getCurrentUser();

        // Absolute redirection URLs may cause spoofing
        $backURL = $this->getBackURL();
        if ($backURL) {
            return $this->redirect($backURL);
        }

        // If a default login dest has been set, redirect to that.
        $defaultLoginDest = Security::config()->get('default_login_dest');
        if ($defaultLoginDest) {
            return $this->redirect($defaultLoginDest);
        }

        // Redirect the user to the page where they came from
        if ($member) {
            // Welcome message
            $message = _t(
                'SilverStripe\\Security\\Member.WELCOMEBACK',
                'Welcome Back, {firstname}',
                ['firstname' => $member->FirstName]
            );
            Security::singleton()->setSessionMessage($message, ValidationResult::TYPE_GOOD);
        }

        // Redirect back
        return $this->redirectBack();
    }

    /**
     * @inheritdoc
     * @internal We want to display pretty error pages so we will relay errors to the PageController.
     * @param int $errorCode
     * @param null $errorMessage
     */
    public function httpError($errorCode, $errorMessage = null)
    {
        return PageController::singleton()->httpError($errorCode, $errorMessage);
    }
}
