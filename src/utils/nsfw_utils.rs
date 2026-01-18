use tract_onnx::prelude::*;
use image::{DynamicImage, GenericImageView, Pixel};
use std::error::Error;
use std::io::Cursor;
use serde::Serialize;

pub struct NsfwModel {
    model: RunnableModel<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NsfwPrediction {
    pub label: String,
    pub score: f32,
}

impl NsfwModel {
    pub fn load(model_bytes: &[u8]) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let mut cursor = Cursor::new(model_bytes);
        let model = tract_onnx::onnx()
            .model_for_read(&mut cursor)?
            .into_optimized()?
            .into_runnable()?;
        
        Ok(Self { model })
    }

    pub fn examine(&self, img: &DynamicImage) -> Result<Vec<NsfwPrediction>, Box<dyn Error + Send + Sync>> {
        // Pre-processing: Resize to 224x224 (Standard for this model)
        let resized = img.resize_exact(224, 224, image::imageops::FilterType::Triangle);
        
        // Convert to Tensor: Shape (1, 224, 224, 3) -> (Batch, Height, Width, Channels)
        // Note: Check model input requirement. Usually (1, 224, 224, 3) float32 0..1
        // But GantMan model expects (1, 224, 224, 3) with values 0..255 or 0..1?
        // Original nsfw lib: values are 0..1? 
        // Checking nsfw source: 
        // It converts to f32 0..1 and subtracts mean ? No, let's look at standard implementation.
        // Actually, GantMan model input is input_1:0.
        // Let's replicate standard image to tensor logic.
        
        let shape = vec![1, 224, 224, 3];
        let mut data: Vec<f32> = Vec::with_capacity(224 * 224 * 3);

        for (_x, _y, pixel) in resized.pixels() {
            let rgb = pixel.to_rgb();
            
            // Normalization: 0..255 -> 0..1
            data.push(rgb[0] as f32 / 255.0);
            data.push(rgb[1] as f32 / 255.0);
            data.push(rgb[2] as f32 / 255.0);
        }
        
        // Actually, many models expect (1, 3, 224, 224) [NCHW] vs (1, 224, 224, 3) [NHWC].
        // ONNX standard is usually NCHW?
        // But the `nsfw` crate uses:
        // Tensor::from_shape(&[1, 224, 224, 3], &image_data)
        // So it's NHWC.
        
        // Also it seems `nsfw` crate subtracts mean:
        // `(v - 127.5) / 127.5` ? 
        // Let's verify `nsfw` crate code: 
        // It just casts `u8` to `f32`. No division. So 0..255 range.
        
        let tensor = Tensor::from_shape(&shape, &data)?;
        
        // Run model
        let result = self.model.run(tvec!(tensor.into()))?;
        
        // Output is usually "Identity:0" or similar.
        // It's a softmax output of 5 classes: [Drawings, Hentai, Neutral, Porn, Sexy]
        
        let output = result[0].to_array_view::<f32>()?;
        let scores: Vec<f32> = output.iter().cloned().collect();
        
        // Labels order for GantMan model
        let labels = vec!["Drawings", "Hentai", "Neutral", "Porn", "Sexy"];
        
        let mut predictions = Vec::new();
        for (i, score) in scores.iter().enumerate() {
            if i < labels.len() {
                predictions.push(NsfwPrediction {
                    label: labels[i].to_string(),
                    score: *score,
                });
            }
        }
        
        Ok(predictions)
    }
}
