import torch
from diffusers import StableDiffusionXLPipeline, UNet2DConditionModel, EulerDiscreteScheduler
from huggingface_hub import hf_hub_download
from safetensors.torch import load_file
from PIL import Image
import random

base = "stabilityai/stable-diffusion-xl-base-1.0"
repo = "ByteDance/SDXL-Lightning"
ckpt = "sdxl_lightning_4step_unet.safetensors"

if torch.backends.mps.is_available():
    device = "mps"
    torch_dtype = torch.float16
else:
    device = "cpu"
    torch_dtype = torch.float32

print(f"Using device: {device}")

try:
    unet = UNet2DConditionModel.from_config(base, subfolder="unet").to(device, torch_dtype)
    unet.load_state_dict(load_file(hf_hub_download(repo, ckpt), device=device))
    pipe = StableDiffusionXLPipeline.from_pretrained(base, unet=unet, torch_dtype=torch_dtype, variant="fp16" if device == "cuda" else None).to(device)
    pipe.scheduler = EulerDiscreteScheduler.from_config(pipe.scheduler.config, timestep_spacing="trailing")

    width = 1584
    height = 392

    gimmicks = [
        "Cybersecurity",
        "Security operation center",
        "fractal data visualizations",
        "stylized binary code",
        "abstract AI consciousness",
        "cybernetic energy flows",
        "encrypted data streams",
        "futuristic control panels",
        "digital lock and key",
        "firewall visualizations",
        "intrusion detection systems",
        "threat intelligence maps",
        "encryption algorithms",
        "security protocols",
        "data breach visualizations",
        "security audit icons",
        "CYSA+ symbol",
        "security shield with checkmark",
        "network security diagrams",
    ]

    random_gimmicks = random.sample(gimmicks, 5)

    # Combined prompt with specific instructions
    prompt = f"AI and Cybersecurity landscape, neat japanese anime, SOLID, STEALTH, SIMPLE SPACIOUS, professional, linkedin cover, no human faces, classy, chainsawman anime nature, only theme, {', '.join(random_gimmicks)}."
    negative_prompt = "human face, people, person, portrait, close-up, photorealistic, realistic, cartoon, writings, cluttered, crowded"

    image = pipe(prompt, negative_prompt=negative_prompt, num_inference_steps=4, guidance_scale=0, width=width, height=height).images[0]

    image.save("linkedin_cover_cybersecurity_classy.png")
    print(f"LinkedIn cover image with cybersecurity elements, classy theme, generated and saved as linkedin_cover_cybersecurity_classy.png.")

except Exception as e:
    print(f"An error occurred: {e}")