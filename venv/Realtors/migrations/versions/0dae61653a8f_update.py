"""update

Revision ID: 0dae61653a8f
Revises: e9a0b201617c
Create Date: 2021-07-28 18:30:08.819103

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0dae61653a8f'
down_revision = 'e9a0b201617c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('contact', sa.String(length=80), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('user', 'contact')
    # ### end Alembic commands ###
