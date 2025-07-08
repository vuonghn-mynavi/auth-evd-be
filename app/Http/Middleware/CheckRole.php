<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class CheckRole
{
    /**
     * Handle an incoming request.
     *
     * @param  Request $request
     * @param  Closure $next
     * @param  string  ...$roles
     *
     * @return
     */
    public function handle(Request $request, Closure $next, ...$roles)
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
            $payload = JWTAuth::getPayload();

            if (!$user) {
                return response()->json([
                    'success' => false,
                    'error' => 'User not found'
                ], 401);
            }

            $userRole = $payload->get('role');

            if (!$userRole) {
                return response()->json([
                    'success' => false,
                    'error' => 'Role not found in token'
                ], 401);
            }

            if (!in_array($userRole, $roles)) {
                return response()->json([
                    'success' => false,
                    'error' => 'Access denied. Required roles: ' . implode(', ', $roles) . '. Your role: ' . $userRole
                ], 403);
            }

            $request->attributes->add([
                'auth_user' => $user,
                'auth_role' => $userRole,
                'jwt_payload' => $payload->toArray()
            ]);

            return $next($request);
        } catch (JWTException $e) {
            return response()->json([
                'success' => false,
                'error' => 'Token not valid: ' . $e->getMessage()
            ], 401);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'error' => 'Authorization error: ' . $e->getMessage()
            ], 500);
        }
    }
}
