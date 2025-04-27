"""Add indexes to users table

Revision ID: e8a7d63f9c3e
Revises: 25d814bc83ed
Create Date: 2025-04-27 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'e8a7d63f9c3e'
down_revision = '25d814bc83ed'  # Updated to match the actual previous migration ID
branch_labels = None
depends_on = None


def upgrade():
    # Add indexes to existing tables - removing email and nickname indexes since they already exist
    op.create_index('idx_users_role', 'users', ['role'])
    op.create_index('idx_users_is_locked', 'users', ['is_locked'])
    op.create_index('idx_users_email_verified', 'users', ['email_verified'])
    op.create_index('idx_users_created_at', 'users', ['created_at'])
    op.create_index('idx_users_updated_at', 'users', ['updated_at'])
    op.create_index('idx_users_role_verified', 'users', ['role', 'email_verified'])


def downgrade():
    # Remove indexes
    op.drop_index('idx_users_role', table_name='users')
    op.drop_index('idx_users_is_locked', table_name='users')
    op.drop_index('idx_users_email_verified', table_name='users')
    op.drop_index('idx_users_created_at', table_name='users')
    op.drop_index('idx_users_updated_at', table_name='users')
    op.drop_index('idx_users_role_verified', table_name='users')