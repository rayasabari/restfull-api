<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Symfony\Component\HttpFoundation\Response;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $fields = $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|unique:users,email',
            'password' => 'required|string|confirmed'
        ]);

        $user = User::create([
            'name' => $fields['name'],
            'email' => $fields['email'],
            'password' => bcrypt($fields['password'])
        ]);

        $data = [
            'message' => 'Register Success!',
            'user' => $user
        ];

        return response()->json($data, Response::HTTP_CREATED);
    }

    public function login(Request $request)
    {
        $fields = $request->validate([
            'email' => 'required|string',
            'password' => 'required|string'
        ]);

        // check email
        $user = User::where('email', $fields['email'])->first();

        // check password
        if (!$user || !Hash::check($fields['password'], $user->password)) {
            return response()->json([
                'message' => 'Bad Request',
            ], Response::HTTP_UNAUTHORIZED);
        }

        $token = $user->createToken('rysbtoken')->plainTextToken;

        $data = [
            'message' => 'Login Success!',
            'token' => $token
        ];

        return response()->json($data, Response::HTTP_OK);
    }

    public function logout(Request $request)
    {
        auth()->user()->tokens()->delete();

        return response([
            'messages' => 'Logged Out!'
        ], Response::HTTP_OK);
    }
}
