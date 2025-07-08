<?php

namespace Database\Seeders;

use App\Models\User;
// use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        User::factory()->admin()->create([
            'name' => 'Admin User',
            'email' => 'admin@test.com',
            'password' => bcrypt('password123'),
        ]);

        User::factory()->manager()->create([
            'name' => 'Manager User',
            'email' => 'manager@test.com',
            'password' => bcrypt('password123'),
        ]);

        User::factory()->user()->create([
            'name' => 'Regular User',
            'email' => 'user@test.com',
            'password' => bcrypt('password123'),
        ]);

        User::factory(5)->create();

        $this->command->info('✅ Created test users:');
        $this->command->info('👑 Admin: admin@test.com / password123');
        $this->command->info('👔 Manager: manager@test.com / password123');
        $this->command->info('👤 User: user@test.com / password123');
        $this->command->info('🎲 5 random users with random roles');
    }
}
