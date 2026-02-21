import requests
import base64
from io import BytesIO
import json

class CaptchaSolver:
    def __init__(self, ocr_server='http://captcha.tangyun.lat:9898/ocr', slide_server='http://captcha.tangyun.lat:9898/slide'):
        """
        初始化验证码识别器
        
        :param ocr_server: OCR识别服务地址
        :param slide_server: 滑块验证码识别服务地址
        """
        self.ocr_server = ocr_server
        self.slide_server = slide_server

    def image_to_base64(self, image_path=None, image_data=None):
        """
        将图片转换为base64编码
        
        :param image_path: 图片文件路径
        :param image_data: 图片二进制数据
        :return: base64编码字符串
        """
        if image_path:
            with open(image_path, "rb") as f:
                image_bytes = f.read()
        elif image_data:
            image_bytes = image_data
        else:
            raise ValueError("必须提供image_path或image_data参数")
            
        return base64.b64encode(image_bytes).decode('utf-8')

    def solve_image_captcha(self, image_path=None, image_data=None):
        """
        识别图像验证码
        
        :param image_path: 验证码图片路径
        :param image_data: 验证码图片二进制数据
        :return: 识别结果
        """
        # 将图片转换为base64
        image_base64 = self.image_to_base64(image_path, image_data)
        
        # 准备请求数据
        payload = {
            "image": image_base64
        }
        
        # 发送请求到OCR服务器
        try:
            response = requests.post(self.ocr_server, json=payload, timeout=10)
            response.raise_for_status()
            
            # 检查响应是否为空
            if not response.text.strip():
                raise Exception("服务器返回空响应")
            
            result = response.json()
            
            if result.get("code") == 0 and result.get("data"):
                return result["data"].strip()
            else:
                error_msg = result.get("message", "未知错误")
                raise Exception(f"验证码识别失败: {error_msg}")
                
        except requests.exceptions.RequestException as e:
            raise Exception(f"网络请求错误: {str(e)}")
        except json.JSONDecodeError as e:
            raise Exception(f"服务器响应格式错误: {str(e)}")
        except Exception as e:
            raise Exception(f"验证码识别出错: {str(e)}")

    def solve_slide_captcha(self, bg_image_path=None, slide_image_path=None, 
                           bg_image_data=None, slide_image_data=None, full_image_data=None):
        """
        识别滑块验证码
        
        :param bg_image_path: 背景图片路径
        :param slide_image_path: 滑块图片路径
        :param bg_image_data: 背景图片二进制数据
        :param slide_image_data: 滑块图片二进制数据
        :param full_image_data: 完整验证码图片二进制数据
        :return: 滑块应移动的距离
        """
        payload = {}
        
        # 如果提供了背景图和滑块图
        if (bg_image_path or bg_image_data) and (slide_image_path or slide_image_data):
            bg_base64 = self.image_to_base64(bg_image_path, bg_image_data)
            slide_base64 = self.image_to_base64(slide_image_path, slide_image_data)
            payload = {
                "bg_image": bg_base64,
                "slide_image": slide_base64
            }
        # 如果提供了完整图片
        elif full_image_data:
            full_base64 = self.image_to_base64(image_data=full_image_data)
            payload = {
                "full_image": full_base64
            }
        else:
            raise ValueError("必须提供背景图和滑块图，或完整的验证码图片")
        
        # 发送请求到滑块验证码服务器
        try:
            response = requests.post(self.slide_server, json=payload, timeout=10)
            response.raise_for_status()
            
            result = response.json()
            
            if result.get("code") == 0 and result.get("data"):
                return result["data"]
            else:
                error_msg = result.get("message", "未知错误")
                raise Exception(f"滑块验证码识别失败: {error_msg}")
                
        except requests.exceptions.RequestException as e:
            raise Exception(f"网络请求错误: {str(e)}")
        except json.JSONDecodeError:
            raise Exception("服务器响应格式错误")
        except Exception as e:
            raise Exception(f"滑块验证码识别出错: {str(e)}")

# 使用示例
if __name__ == "__main__":
    # 创建验证码识别器实例
    solver = CaptchaSolver()
    
    # 示例1: 识别图像验证码
    try:
        # 替换为实际的验证码图片路径
        captcha_result = solver.solve_image_captcha(image_path="captcha.png")
        print(f"图像验证码识别结果: {captcha_result}")
    except Exception as e:
        print(f"识别失败: {e}")
    
    # 示例2: 识别滑块验证码
    try:
        # 替换为实际的背景图和滑块图路径
        slide_result = solver.solve_slide_captcha(
            bg_image_path="bg.png",
            slide_image_path="slide.png"
        )
        print(f"滑块验证码识别结果: {slide_result}")
    except Exception as e:
        print(f"识别失败: {e}")