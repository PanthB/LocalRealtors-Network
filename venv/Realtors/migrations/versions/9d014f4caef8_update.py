"""update

Revision ID: 9d014f4caef8
Revises: c1e75323780b
Create Date: 2021-07-24 18:52:31.293056

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9d014f4caef8'
down_revision = 'c1e75323780b'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('type', sa.String(length=120), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('user', 'type')
    # ### end Alembic commands ###
