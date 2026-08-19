<?php

use App\Http\Controllers\AuthController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;


// Public Authentication Routes
Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);

// Protected Authentication Routes
Route::middleware(['auth:sanctum','abilities:access-api'])->group(function () {
    Route::post('/logout', [AuthController::class, 'logout']);
    
    // (Preview of Part 2) Protected user profile endpoint
    Route::get('/user', function (Request $request) {
        return response()->json([
            'user' => $request->user()
        ]);
    });
});

// Route requiring the Refresh Token ability specifically
Route::middleware(['auth:sanctum', 'abilities:issue-access-token'])->group(function () {
    Route::post('/refresh', [AuthController::class, 'refresh']);
});

