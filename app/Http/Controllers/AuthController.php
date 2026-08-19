<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    //
    public function register(Request $request)
    {
        $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
            'password' => ['required', 'string', 'min:8'],
        ]);
    
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);
    
        return $this->generateTokenPair($user, 'Registration successful', 201);
    }

    public function login(Request $request)
    {
        $request->validate([
            'email' => ['required', 'string', 'email'],
            'password' => ['required', 'string'],
        ]);

        $user = User::where('email', $request->email)->first();

        if (! $user || ! Hash::check($request->password, $user->password)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        return $this->generateTokenPair($user, 'Login successful', 200);
    }

    // Refresh Endpoint: Takes a valid Refresh Token and returns a new Access Token
    public function refresh(Request $request)
    {
        $user = $request->user();
    
        // Optional: Revoke the current refresh token to enforce single-use rotation policy
        $user->currentAccessToken()->delete();
    
        // Issue a fresh short-lived Access Token
        $accessTokenExpiry = now()->addMinutes(15);
        $newAccessToken = $user->createToken('access_token', ['access-api'], $accessTokenExpiry)->plainTextToken;
    
        return response()->json([
            'message' => 'Access token refreshed successfully',
            'access_token' => $newAccessToken,
            'token_type' => 'Bearer',
            'expires_in' => 900
        ], 200);
    }
    
        // Revoke the current user token (Logout)
    public function logout(Request $request)
    {
        // Revoke the token that was used to authenticate the current request
        $request->user()->currentAccessToken()->delete();

        return response()->json([
            'message' => 'Successfully logged out'
        ], 200);
    }
    private function generateTokenPrinter(User $user, string $message, int $status)
    {
        // Clear old tokens if you want to keep tracking clean (optional)
        // $user->tokens()->delete();
    
        $accessTokenExpiry = now()->addMinutes(3);
        $refreshTokenExpiry = now()->addMinutes(30);
    
        // 1. Create short-lived Access Token
        $accessToken = $user->createToken('access_token', ['access-api'], $accessTokenExpiry)->plainTextToken;
    
        // 2. Create long-lived Refresh Token
        $refreshToken = $user->createToken('refresh_token', ['issue-access-token'], $refreshTokenExpiry)->plainTextToken;
    
        return response()->json([
            'message' => $message,
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
            'token_type' => 'Bearer',
            'expires_in' => 180, // 15 minutes in seconds
            'user' => $user
        ], $status);
    }
    
    // Alias wrapper for cleaner code readability
    private function generateTokenPair(User $user, string $message, int $status)
    {
        return $this->generateTokenPrinter($user, $message, $status);
    }
    
    
}

// public function register(Request $request)
    // {
    //     $request->validate([
    //         'name' => ['required', 'string', 'max:255'],
    //         'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
    //         'password' => ['required', 'string', 'min:8'],
    //     ]);

    //     $user = User::create([
    //         'name' => $request->name,
    //         'email' => $request->email,
    //         'password' => Hash::make($request->password),
    //     ]);

    //     $token = $user->createToken('auth_token')->plainTextToken;

    //     return response()->json([
    //         'message' => 'Registration successful',
    //         'access_token' => $token,
    //         'token_type' => 'Bearer',
    //         'user' => $user
    //     ], 201);
    // }

    // Authenticate user credentials and return a Bearer token

    // public function login(Request $request)
    // {
    //     $request->validate([
    //         'email' => ['required', 'string', 'email'],
    //         'password' => ['required', 'string'],
    //     ]);

    //     $user = User::where('email', $request->email)->first();

    //     if (! $user || ! Hash::check($request->password, $user->password)) {
    //         throw ValidationException::withMessages([
    //             'email' => ['The provided credentials are incorrect.'],
    //         ]);
    //     }

    //     // Optional: Revoke previous tokens if you want single-device login
    //     // $user->tokens()->delete();
    //     $token = $user->createToken('auth_token')->plainTextToken;
    //     return response()->json([
    //         'message' => 'Login successful',
    //         'access_token' => $token,
    //         'token_type' => 'Bearer',
    //         'user' => $user
    //     ], 200);
    // }
