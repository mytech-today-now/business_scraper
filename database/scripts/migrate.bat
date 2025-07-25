@echo off
setlocal enabledelayedexpansion

REM Database Migration Script for Business Scraper (Windows)
REM Usage: migrate.bat [command] [options]
REM Commands: up, down, status, reset

REM Configuration
if "%DB_NAME%"=="" set DB_NAME=business_scraper_db
if "%DB_USER%"=="" set DB_USER=postgres
if "%DB_HOST%"=="" set DB_HOST=localhost
if "%DB_PORT%"=="" set DB_PORT=5432

set SCRIPT_DIR=%~dp0
set DATABASE_DIR=%SCRIPT_DIR%..
set SCHEMA_DIR=%DATABASE_DIR%\schema
set MIGRATIONS_DIR=%DATABASE_DIR%\migrations

REM Check if psql is available
where psql >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] psql command not found. Please install PostgreSQL client tools.
    exit /b 1
)

REM Parse command line arguments
set COMMAND=%1
set VERSION=%2

if "%COMMAND%"=="" set COMMAND=help

goto %COMMAND% 2>nul || goto unknown_command

:up
echo [INFO] Running migrations...
call :check_database
if %errorlevel% neq 0 exit /b 1

call :init_migration_tracking

REM Apply migrations (simplified - only handles 001 for now)
call :check_migration_applied 001
if %errorlevel% equ 0 (
    echo [INFO] Migration 001 already applied, skipping
) else (
    echo [INFO] Applying migration 001: initial_schema
    call :apply_migration 001 initial_schema "%SCHEMA_DIR%\001_initial_schema.sql"
    if %errorlevel% neq 0 exit /b 1
)

echo [SUCCESS] All migrations completed
goto :eof

:down
if "%VERSION%"=="" (
    echo [ERROR] Target version required for rollback
    exit /b 1
)

echo [INFO] Rolling back to version %VERSION%...
call :check_database
if %errorlevel% neq 0 exit /b 1

REM Simple rollback for version 001
if "%VERSION%"=="000" (
    call :check_migration_applied 001
    if %errorlevel% equ 1 (
        echo [INFO] Rolling back migration 001
        call :rollback_migration 001 initial_schema "%SCHEMA_DIR%\001_initial_schema_rollback.sql"
        if %errorlevel% neq 0 exit /b 1
    )
)

echo [SUCCESS] Rollback completed
goto :eof

:status
echo [INFO] Migration Status:
echo.
call :psql_exec -c "SELECT version, name, status, applied_at, execution_time_ms FROM migration_status ORDER BY version;"
goto :eof

:reset
echo [WARNING] This will drop all tables and reset the database. Are you sure? (y/N)
set /p response=
if /i "%response%"=="y" (
    echo [INFO] Resetting database...
    call :psql_exec -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public; GRANT ALL ON SCHEMA public TO %DB_USER%; GRANT ALL ON SCHEMA public TO public;"
    if %errorlevel% equ 0 (
        echo [SUCCESS] Database reset completed
        call :up
    ) else (
        echo [ERROR] Failed to reset database
        exit /b 1
    )
) else (
    echo [INFO] Reset cancelled
)
goto :eof

:help
echo Database Migration Script for Business Scraper
echo.
echo Usage: %0 [command] [options]
echo.
echo Commands:
echo   up [version]     Apply migrations up to specified version (or all if no version)
echo   down ^<version^>   Rollback migrations to specified version
echo   status           Show current migration status
echo   reset            Reset database and re-apply all migrations
echo   help             Show this help message
echo.
echo Environment Variables:
echo   DB_NAME          Database name (default: business_scraper_db)
echo   DB_USER          Database user (default: postgres)
echo   DB_PASSWORD      Database password
echo   DB_HOST          Database host (default: localhost)
echo   DB_PORT          Database port (default: 5432)
echo.
echo Examples:
echo   %0 up            # Apply all pending migrations
echo   %0 down 000      # Rollback all migrations
echo   %0 status        # Show migration status
goto :eof

:unknown_command
echo [ERROR] Unknown command: %COMMAND%
echo.
call :help
exit /b 1

REM Helper functions

:check_database
psql -h %DB_HOST% -p %DB_PORT% -U %DB_USER% -lqt | findstr /C:"%DB_NAME%" >nul
if %errorlevel% neq 0 (
    echo [ERROR] Database '%DB_NAME%' does not exist. Please create it first.
    exit /b 1
)
exit /b 0

:init_migration_tracking
echo [INFO] Initializing migration tracking...
call :psql_exec -f "%MIGRATIONS_DIR%\migration_tracker.sql" >nul 2>&1
if %errorlevel% equ 0 (
    echo [SUCCESS] Migration tracking initialized
) else (
    echo [WARNING] Migration tracking may already be initialized
)
exit /b 0

:check_migration_applied
set migration_version=%1
for /f "tokens=*" %%i in ('call :psql_exec -t -c "SELECT is_migration_applied('%migration_version%');" 2^>nul') do set result=%%i
set result=%result: =%
if "%result%"=="t" (
    exit /b 0
) else (
    exit /b 1
)

:apply_migration
set version=%1
set name=%2
set file=%3

echo [INFO] Applying migration %version%: %name%

call :psql_exec -f "%file%"
if %errorlevel% equ 0 (
    call :psql_exec -c "SELECT record_migration('%version%', '%name%', 'batch_script', NULL);"
    echo [SUCCESS] Migration %version% applied successfully
    exit /b 0
) else (
    echo [ERROR] Failed to apply migration %version%
    exit /b 1
)

:rollback_migration
set version=%1
set name=%2
set file=%3

echo [INFO] Rolling back migration %version%: %name%

call :psql_exec -f "%file%"
if %errorlevel% equ 0 (
    call :psql_exec -c "SELECT remove_migration('%version%');"
    echo [SUCCESS] Migration %version% rolled back successfully
    exit /b 0
) else (
    echo [ERROR] Failed to rollback migration %version%
    exit /b 1
)

:psql_exec
psql -h %DB_HOST% -p %DB_PORT% -U %DB_USER% -d %DB_NAME% -v ON_ERROR_STOP=1 %*
exit /b %errorlevel%
