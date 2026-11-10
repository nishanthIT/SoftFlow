"""Optional product/version declarations, shared by upload and reanalysis APIs."""
from pydantic import BaseModel,Field,field_validator,model_validator

class SoftwareIdentity(BaseModel):
    name: str = Field(max_length=160)
    version: str = Field(max_length=128)
    vendor: str = Field(default='',max_length=160)

    @field_validator('name','version','vendor')
    @classmethod
    def clean(cls,value):
        if any(ord(c)<32 or ord(c)==127 for c in value):raise ValueError('Control characters are not allowed')
        return value.strip()

    @model_validator(mode='after')
    def complete(self):
        if not self.name or not self.version:raise ValueError('Provide both software name and version')
        return self
