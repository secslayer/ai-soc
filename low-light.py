import torch
from diffusers import StableDiffusionXLImg2ImgPipeline
from PIL import Image

try:
    pipe = StableDiffusionXLImg2ImgPipeline.from_pretrained(
        "stabilityai/stable-diffusion-xl-refiner-1.0", torch_dtype=torch.float16, variant="fp16", use_safetensors=True
    )
    pipe = pipe.to("mps")  # Change to "cuda" if you have a CUDA GPU

    # Load image from local file
    local_image_path = "./IMG-20250304-WA0027.jpg"  # Replace with your image file path
    init_image = Image.open(local_image_path).convert("RGB")

    # Focus on lighting changes in the prompt
    prompt = "enhance lighting, increase brightness, add natural light, subtle highlights, soft shadows, " \
             "photorealistic lighting, cinematic lighting" 

    image = pipe(prompt, image=init_image).images[0]

    image.save("enhanced_lighting_image.png")
    print("Image saved as enhanced_lighting_image.png")

except FileNotFoundError:
    print(f"Error: Image file not found at {local_image_path}")
except Exception as e:
    print(f"An error occurred: {e}")