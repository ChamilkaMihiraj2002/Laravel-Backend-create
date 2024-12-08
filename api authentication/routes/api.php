<?php

use App\Http\Controllers\Api\ProductController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;

Route::post("/login", [AuthController::class,"login"]);
Route::post("/register", [AuthController::class,"register"]);

Route::middleware(['auth:sanctum'])->group(function () {
    Route::post("/logout", [AuthController::class,"logout"]);
    Route::get("/profile", [AuthController::class,"profile"]);
    Route::apiResource('products', ProductController::class);
});




Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');