from marshmallow import Serializer

###### USER SERIALIZER #####
class UserSerializer(Serializer):
    class Meta:
        # Fields to expose
        fields = ('username')

#Return the user data in json format
def get_user_serialized(user):
    return UserSerializer(user).data