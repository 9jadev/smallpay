<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\User;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{

    public $loginAfterSignUp = true;

    public function register(Request $request)
    {
      $validator = Validator::make($request->all(), [
        'firstname' => ['required', 'string', 'max:255'],
        'lastname' => ['required', 'string', 'max:255'],
        'email' => ['required', 'string', 'email', 'max:255', 'unique:users,email'],
        'phone' => ['required', 'string', 'max:16', 'unique:users,phone'],
        'password' => ['required', 'string', 'min:8', 'confirmed'],
        // 'password_confirmation' remenber to use this as a field will validating
    ]);

    if ($validator->fails()) {    
      return response()->json($validator->messages(), 200);
    }

      $user = User::create([
        'firstname' => $request->firstname,
        'lastname' => $request->lastname,
        'email' => $request->email,
        'phone' => $request->phone,
        'password' => bcrypt($request->password),
      ]);
    
      if ($user) {
        $token = auth()->guard('api')->login($user);
     
        return $this->respondWithToken($token); 
      }
    }

    public function login(Request $request)
    {
      $credentials = $request->only(['email', 'password']);
      
      if (!$token = auth()->guard('api')->attempt($credentials)) {
        return response()->json(['error' => 'Email and Password are not correct'], 401);
      }

      return response()->json([
        'success' => true, 
        'access_token' => $token,
        'token_type' => 'bearer'
      ]);  
    }
    public function getAuthUser(Request $request)
    {
        return response()->json(auth()->guard('api')->user());
    }
    public function logout()
    {
        auth()->guard('api')->logout();
        return response()->json(['message'=>'Successfully logged out']);
    }
    protected function respondWithToken($token)
    {
      return response()->json([
        'success' => true, 
        'access_token' => $token,
        'token_type' => 'bearer',
        'expires_in' => auth('api')->factory()->getTTL() * 60
      ]);
    }

}