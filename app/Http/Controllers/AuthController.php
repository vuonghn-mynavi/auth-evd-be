<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Exception;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        try {
            if (!$token = JWTAuth::attempt($credentials)) {
                return response()->json([
                    'success' => false,
                    'error' => 'Invalid credentials'
                ], 401);
            }
        } catch (JWTException $e) {
            return response()->json([
                'success' => false,
                'error' => 'Could not create token'
            ], 500);
        }
        $user = JWTAuth::user();
        $refreshToken = $this->createRefreshToken($user);

        $decodedPayload = JWTAuth::setToken($token)->getPayload();

        return response()->json([
            'success' => true,
            'message' => 'Login successful',
            'user' => $user,
            'access_token' => $token,
            'refresh_token' => $refreshToken,
            'token_type' => 'bearer',
            'expires_in' => (int)config('jwt.ttl') * 60,
            'payload_info' => [
                'user_id' => $decodedPayload->get('sub'),
                'role' => $decodedPayload->get('role'),
                'name' => $decodedPayload->get('name'),
                'email' => $decodedPayload->get('email'),
                'issued_at' => date('Y-m-d H:i:s', $decodedPayload->get('iat')),
                'expires_at' => date('Y-m-d H:i:s', $decodedPayload->get('exp'))
            ]
        ])->cookie('jwt_token', $token, (int)config('jwt.ttl'), '/', null, true, true, false, 'strict');
    }

    public function refresh(Request $request)
    {
        try {
            $refreshToken = $request->refresh_token ?? $request->header('X-Refresh-Token');

            if (!$refreshToken) {
                return response()->json([
                    'success' => false,
                    'error' => 'Refresh token not provided'
                ], 401);
            }

            $user = $this->validateRefreshToken($refreshToken);

            if (!$user) {
                return response()->json([
                    'success' => false,
                    'error' => 'Invalid or expired refresh token'
                ], 401);
            }

            $newToken = JWTAuth::fromUser($user);
            $newRefreshToken = $this->createRefreshToken($user);

            $decodedPayload = JWTAuth::setToken($newToken)->getPayload();

            return response()->json([
                'success' => true,
                'message' => 'Token refreshed successfully',
                'access_token' => $newToken,
                'refresh_token' => $newRefreshToken,
                'token_type' => 'bearer',
                'expires_in' => config('jwt.ttl') * 60,
                'payload_info' => [
                    'user_id' => $decodedPayload->get('sub'),
                    'role' => $decodedPayload->get('role'),
                    'name' => $decodedPayload->get('name'),
                    'email' => $decodedPayload->get('email'),
                    'issued_at' => date('Y-m-d H:i:s', $decodedPayload->get('iat')),
                    'expires_at' => date('Y-m-d H:i:s', $decodedPayload->get('exp'))
                ]
            ])->cookie('jwt_token', $newToken, (int)config('jwt.ttl'), '/', null, true, true, false, 'strict');
        } catch (JWTException $e) {
            return response()->json([
                'success' => false,
                'error' => 'Could not refresh token'
            ], 500);
        }
    }

    public function logout(Request $request)
    {
        try {
            $token = $request->cookie('jwt_token') ?? JWTAuth::getToken();

            if ($token) {
                JWTAuth::setToken($token)->invalidate();
            }

            return response()->json([
                'success' => true,
                'message' => 'Successfully logged out'
            ])->cookie('jwt_token', '', -1, '/', null, true, true, false, 'strict');
        } catch (JWTException $e) {
            return response()->json([
                'success' => false,
                'error' => 'Failed to logout, but clearing cookie'
            ])->cookie('jwt_token', '', -1, '/', null, true, true, false, 'strict');
        }
    }

    public function me()
    {
        try {
            $user = JWTAuth::user();
            $token = JWTAuth::getToken();
            $payload = JWTAuth::getPayload();

            return response()->json([
                'success' => true,
                'user' => $user,
                'token_info' => [
                    'user_id' => $payload->get('sub'),
                    'role' => $payload->get('role'),
                    'name' => $payload->get('name'),
                    'email' => $payload->get('email'),
                    'issued_at' => date('Y-m-d H:i:s', $payload->get('iat')),
                    'expires_at' => date('Y-m-d H:i:s', $payload->get('exp')),
                    'time_until_expiry' => $payload->get('exp') - time() . ' seconds'
                ]
            ]);
        } catch (JWTException $e) {
            return response()->json([
                'success' => false,
                'error' => 'Token not valid'
            ], 401);
        }
    }

    public function decodeToken(Request $request)
    {
        try {
            $token = $request->token ?? $request->cookie('jwt_token') ?? JWTAuth::getToken();

            if (!$token) {
                return response()->json([
                    'success' => false,
                    'error' => 'No token provided'
                ], 400);
            }

            $payload = JWTAuth::setToken($token)->getPayload();

            return response()->json([
                'success' => true,
                'decoded_payload' => [
                    'sub' => $payload->get('sub'),
                    'role' => $payload->get('role'),
                    'name' => $payload->get('name'),
                    'email' => $payload->get('email'),
                    'iat' => $payload->get('iat'),
                    'exp' => $payload->get('exp'),
                    'nbf' => $payload->get('nbf'),
                    'iss' => $payload->get('iss'),
                    'jti' => $payload->get('jti'),
                    'readable_times' => [
                        'issued_at' => date('Y-m-d H:i:s', $payload->get('iat')),
                        'expires_at' => date('Y-m-d H:i:s', $payload->get('exp')),
                        'not_before' => date('Y-m-d H:i:s', $payload->get('nbf'))
                    ]
                ]
            ]);
        } catch (JWTException $e) {
            return response()->json([
                'success' => false,
                'error' => 'Invalid token'
            ], 401);
        }
    }

    private function createRefreshToken($user)
    {
        $data = [
            'user_id' => $user->id,
            'role' => $user->role,
            'random' => rand() . time(),
            'iat' => time(),
            'exp' => time() + (config('jwt.refresh_ttl') * 60)
        ];

        return base64_encode(json_encode($data));
    }

    private function validateRefreshToken($token)
    {
        try {
            $data = json_decode(base64_decode($token), true);

            if (!$data || !isset($data['exp']) || !isset($data['user_id'])) {
                return null;
            }

            if (time() > $data['exp']) {
                return null;
            }

            $user = User::find($data['user_id']);

            if (!$user) {
                return null;
            }

            if (isset($data['role']) && $data['role'] !== $user->role) {
                return null;
            }

            return $user;
        } catch (Exception $e) {
            return null;
        }
    }
}
