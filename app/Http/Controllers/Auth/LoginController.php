<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Providers\RouteServiceProvider;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use App\Models\User;

class LoginController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles authenticating users for the application and
    | redirecting them to your home screen. The controller uses a trait
    | to conveniently provide its functionality to your applications.
    |
    */

    use AuthenticatesUsers;

    /**
     * Where to redirect users after login.
     *
     * @var string
     */
    protected $redirectTo = RouteServiceProvider::HOME;

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest')->except('logout');
    }

    public function showLoginForm(Request $request)
    {
        return redirect(env('LOGIN_URL') . '?callback=' . route('callback'));
    }

    public function callback(Request $request)
    {
        $response = Http::withoutVerifying()
            ->post(env('LOGIN_TOKEN_API'), [
                'token' => $request->login_token
            ]);

        if ($response->successful()) {
            $admin = User::firstOrCreate([
                'email' => $response->json('email')
            ]);

            $this->guard()->login($admin);

            // Revoke token
            $revokeResponse = Http::withBasicAuth(env('AWS_COGNITO_CLIENT_ID'), env('AWS_COGNITO_CLIENT_SECRET'))
                ->asForm()
                ->post(env('AWS_COGNITO_DOMAIN') . '/oauth2/revoke', [
                    'token' => $request->refresh_token
                ]);

            return redirect()->route('home');
        }

        abort(403);
    }
}
