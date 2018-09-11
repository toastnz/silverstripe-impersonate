<?php

namespace MaximeRainville\Impersonate;

use SilverStripe\Control\RequestHandler;
use SilverStripe\Forms\DropdownField;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\Form;
use SilverStripe\Forms\FormAction;
use SilverStripe\Forms\HiddenField;
use SilverStripe\Forms\Validator;
use SilverStripe\Security\LoginForm as SSLoginForm;
use SilverStripe\Security\Member;

/**
 * Handle login requests from MaximeRainville\Auth0\Authenticator.
 *
 * @internal Mostly copied from the regular LoginHandler. Unfortunately, the regular login handler is tightly coupled
 * with the MemberLoginForm, which makes our work a bit more difficult here.
 */
class LoginForm extends SSLoginForm
{

    public function __construct(RequestHandler $controller = null, $name = self::DEFAULT_NAME, Validator $validator = null)
    {
        $this->controller = $controller;
        parent::__construct($controller, $name, $this->getFormFields(), $this->getFormActions(), $validator);
    }

    public function FormName()
    {
        return 'ImpersonateLoginForm';
    }

    /**
     * Return the title of the form for use in the frontend
     * For tabs with multiple login methods, for example.
     * This replaces the old `get_name` method
     * @return string
     */
    public function getAuthenticatorName()
    {
        return _t(self::class . '.AuthenticatorName', 'Impersonate');
    }

    /**
     * Required FieldList creation on a LoginForm
     *
     * @return FieldList
     */
    protected function getFormFields()
    {
        $backURL = $this->controller->getRequest()->getVar('BackURL');
        return  FieldList::create([
            HiddenField::create('BackURL', 'BackURL',  $backURL),
            DropdownField::create('MemberID', 'Member', Member::get()->map())
        ]);
    }

    /**
     * Required FieldList creation for the login actions on this LoginForm
     *
     * @return FieldList
     */
    protected function getFormActions()
    {
        return FieldList::create([
            FormAction::create(
                'doLogin',
                _t(self::class . '.Action', 'Impersonate')
            )]
        );
    }

}
