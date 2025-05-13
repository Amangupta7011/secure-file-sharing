import os

class Config:
    # MongoDB connection string
    MONGO_URI = "mongodb+srv://amanranjeet7011:amanranjeet7011@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority"
    
    # Other configurations
    SECRET_KEY = "your-secret-key-here"
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
    ALLOWED_EXTENSIONS = {'pptx', 'docx', 'xlsx'}