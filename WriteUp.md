# RE1
Kiểm tra file với ExeInfo để xem được 1 số thông tin cơ bản của file

![image](https://github.com/daglongg/FPTU-Secathon-2024/assets/138242812/029785db-698b-40cf-83b1-b5cd02a94927)

Phân tích tĩnh file này với IDA64. Ở đây ta thấy chường trình có 2 aray là v7 và v8. Đoạn mã dưới yêu cầu người dùng nhập khóa bản quyền, kiểm tra định dạng của khóa bản quyền đó theo định dạng `FUSec{<38 ký tự>}`, và sau đó xác minh tính hợp lệ của phần 38 ký tự bằng hàm `check_license_key` . Nếu tất cả các điều kiện đều thỏa mãn, chương trình sẽ in ra `Correct key!`, nếu không sẽ in `Incorrect key.`.

![image](https://github.com/daglongg/FPTU-Secathon-2024/assets/138242812/1387f02c-cd78-49f6-b77b-a0390a127d6c)

Trong hàm `check_license_key` ta thấy nó đang lấy từng giá trị của v7 trừ đi từng giá trị của v8 và so sánh với chuỗi đầu mình nhập vào. Nếu sai thì return 0 còn đúng thì ngược lại.

![image](https://github.com/daglongg/FPTU-Secathon-2024/assets/138242812/8c38785d-ca7f-4e4a-9099-ffdb18533b0d)

Tôi đã viết 1 scrip 

```
def compare_arrays():
    v7 = [
        0xA8, 0xC1, 0x7A, 0xAC, 0x9E, 0x6C, 0xCE, 0x99, 
        0xAF, 0xAF, 0xC2, 0xBD, 0x8D, 0x7F, 0x65, 0xCA, 
        0xD0, 0x74, 0x95, 0xA0, 0x92, 0xB3, 0x72, 0x8F, 
        0xBB, 0x9F, 0x7E, 0x6D, 0xAE, 0x9C, 0xB9, 0x78, 
        0xA4, 0xBD, 0x70, 0x78, 0x7B, 0x91]
    v8 = [
        0x35, 0x57, 0x16, 0x49, 0x30, 0x1, 0x5B, 0x35, 
        0x3A, 0x3E, 0x59, 0x4A, 0x23, 0x1C, 0x1, 0x5C, 
        0x63, 0x11, 0x29, 0x2D, 0x1D, 0x4F, 0xA, 0x2C, 
        0x44, 0x3A, 0xB, 0xC, 0x48, 0x26, 0x53, 0x2, 
        0x43, 0x4A, 0xC, 0x5, 0x17, 0x2D]
    a1 = [0] * 38  # Khởi tạo mảng a1 với 38 phần tử bằng 0
    
    for i in range(38):
            a1[i] = (v7[i]) - (v8[i])
            print(a1[i])


# Gọi hàm để tính toán và in ra giá trị của từng phần tử trong a1
compare_arrays()
```
và tôi có flag là : `FUSEC{sjdcnksduqisjcdnmclsudhcwesafvfvasdsdd}`

# RE2
Kiểm tra file với ExeInfo để xem được 1 số thông tin cơ bản của file

![image](https://github.com/daglongg/FPTU-Secathon-2024/assets/138242812/731c3be6-b5c0-4c6f-a0a8-3fede262d376)\


Phân tích tĩnh file này với IDA64. Ở đây ta thấy chương trình sẽ yêu cầu ta nhập vào UserName và License Key. Sau đó License Key sẽ được modifyString và được cho vào hàm compare để kiểm tra. Logic bài này rất đơn giản.

![image](https://github.com/daglongg/FPTU-Secathon-2024/assets/138242812/24354886-d515-4b80-91cc-af6c3a522741)


Trong hàm modifyString ta thấy nó đang đảo ngược lại đoạn các kí tự. 

![image](https://github.com/daglongg/FPTU-Secathon-2024/assets/138242812/f6df6a02-9c70-4946-801c-a8db3853caca)

Còn hàm compare user name sẽ được đi qua `generateSerial` và trả ra được 1 string. Trong hàm `generateSerial` thì ta thấy username đã được add thêm vào và được so với 171 sau đó thì sẽ biến chúng từu chữ thường thành chữ hoa trong hàm `toupper`

![image](https://github.com/daglongg/FPTU-Secathon-2024/assets/138242812/f750c3be-55fc-4cc4-ba0b-bb39879928ae)

Ở đây tôi đã viết 1 đoạn srip 

```
a = "fptyoufoundme"
resul = []

for i in range(len(a)):
    print(a[i])
    xor_result = ord(a[i]) ^ 171
    resul.append(xor_result)
    print(hex(xor_result))

# Nếu bạn muốn xem toàn bộ chuỗi kết quả sau khi XOR dưới dạng hex
result_hex = ' '.join([hex(x) for x in resul])
print("Resulting hex string:", result_hex)
```
Và đảo ngược lại và ta có flag là: `FUSEC{ec6cfc5cedc4cdec4d2dfdbddc}`

# RE3
Kiểm tra file với ExeInfo để xem được 1 số thông tin cơ bản của file. Ở đây tôi phát hiện file này đã được pack lại bằng UPX nhằm che giấu mã nguồn.

![image](https://github.com/daglongg/FPTU-Secathon-2024/assets/138242812/ab5b214f-3b04-4a08-84b1-555fd13fb2f8)

Unpack và bắt đầu phân tích với IDA64. Ở đây ta thấy chương trình kiểm tra các đối số dòng lệnh, đảm bảo rằng:
- Số lượng đối số là 3.
- Đối số thứ nhất là "get_flag".
Nếu các điều kiện trên không thỏa mãn, chương trình sẽ in ra thông báo lỗi và thoát với mã trạng thái 1. Nếu các điều kiện thỏa mãn, chương trình sẽ gọi hàm `decrypt_flag` với đối số thứ hai và thoát với mã trạng thái 0.

![image](https://github.com/daglongg/FPTU-Secathon-2024/assets/138242812/83d4f13a-08a2-4bd7-94f6-7ae1c9e6bd42)

Vào hàm `decrypt_flag` ta thấy nó sẽ mã hóa đoạn string và in ra màn hình. Vậy việc ủa chúng ta raasrt đơn giản và chỉ cần debug và có flag thôi

![image](https://github.com/daglongg/FPTU-Secathon-2024/assets/138242812/707b3a06-fad3-4528-89b2-2fe606fc4870)

Flag: `FUSec{Y0ugotm2friendscongrat}`

# Horrible_childhood_memories

Ở đây ta thấy đây là chương trình thi của ĐH FPT (Ao that day). 

![image](https://github.com/daglongg/FPTU-Secathon-2024/assets/138242812/4ea91232-7c0d-48a5-9e44-50a97460e2db)\

Ở đây ta thấy có rất nhiêu file dll và 1 file EOS. Tôi đã kiểm tra file EOS tới ExeInfo.

![image](https://github.com/daglongg/FPTU-Secathon-2024/assets/138242812/3eb24fd3-ecb4-4f8e-8d1a-5e60254f7c32)

CHo vào dnSpy64 để đọc mã nguồn vì nó đang được viết bằng C#. Ở đây ta chú ý tới dòng 343. T thấy ở đây đoạn mã kiểm tra mã kỳ thi người dùng nhập vào. Nếu mã kỳ thi sau khi mã hóa Base64 khớp với một chuỗi đích xác định ("FHfAmGaxK75wQ809PnYSQgUYK8jYAexSmg5z"), chương trình hiển thị thông báo chúc mừng và cho phép người dùng biết mã kỳ thi đúng. Nếu không khớp, chương trình hiển thị thông báo lỗi cho biết mã kỳ thi không hợp lệ.

![image](https://github.com/daglongg/FPTU-Secathon-2024/assets/138242812/f3527596-b362-411b-a4dc-dd226ad537ea)

Ở trong hàm `Base64Encoding` ta thấy 
Hàm `Base64Encoding` thực hiện các bước sau:
- Kiểm tra và làm đầy mảng dữ liệu sao cho độ dài chia hết cho 3.
- Chuyển đổi mỗi nhóm 3 byte thành 4 byte Base64.
- Ánh xạ các giá trị 6-bit thành các ký tự Base64.
- Thêm các ký tự '=' để làm đầy (padding) nếu cần thiết.
- Trả về mảng ký tự chứa chuỗi Base64 đã mã hóa.

và hàm chúng ta cần quan tâm là đoạn này

![image](https://github.com/daglongg/FPTU-Secathon-2024/assets/138242812/822d1552-a220-4d96-8a5b-613e8c60285c)

Ở đây nó hiểu nôm na là mã hóa base64 với 1 đoạn string và cục thể là `abcdefghijklmABCDEFGHIJKLMNOPQRSTUVWXYZnopqrstuvwxyz9876543210+/`

![image](https://github.com/daglongg/FPTU-Secathon-2024/assets/138242812/c9128c0d-3a2d-466d-a36b-1a4fc3ab27a7)

Và ta có flag: `FUSec{IAM101_n0w_try_the_Re4L_0n3}`

# MiniSteg

Kiểm tra file với ExeInfo để xem được 1 số thông tin cơ bản của file.

![image](https://github.com/daglongg/FPTU-Secathon-2024/assets/138242812/e2550d33-54e7-425d-a51c-2d9ff4a13776)

Ở đây tôi thấy chương trình có logic đơn giản là gọi tới 2 funtion. 

![image](https://github.com/daglongg/FPTU-Secathon-2024/assets/138242812/9f18ae7a-0a53-4b4e-847c-c7ee60ff1e35)

Đi sâu vào nó ta thấy funtion `sub_402390()` nó dường như đang thực hiện một số thao tác liên quan đến thời gian hệ thống, ID của quá trình và luồng. CÒn funtion thứ 2 ta chú ý tới dòng 147. 

![image](https://github.com/daglongg/FPTU-Secathon-2024/assets/138242812/6884787a-a84f-4d89-95b7-237d7b635bf9)

Đoạn này ta thấy giống với bài RE3.

![image](https://github.com/daglongg/FPTU-Secathon-2024/assets/138242812/fe524b1c-854b-40c3-94ef-cb83e2ab1cc3)

Các kí tự của v4 đang được tính toán và trả ra 1 str.

![image](https://github.com/daglongg/FPTU-Secathon-2024/assets/138242812/c1e1aea9-ed73-4d09-8042-cd82ee170104)

Ở đây tôi sẽ viết lại scrip để tính toán

```
v4 = [
    0xD1, 0xEF, 0x1C, 0x04, 0x06, 0xF4, 0xF6, 0xE7, 0x0F, 0xEC, 0x00, 0x16, 0xD1, 0xFA, 0x00, 0x18,
    0xF5, 0x00, 0x18, 0xD1, 0xE9, 0x00, 0x18, 0xD1, 0xEA, 0x00, 0xE6, 0xE5, 0xD2, 0xE9, 0x00, 0xD1
]

# Danh sách để lưu kết quả sau khi tính toán
v3 = []

# Vòng lặp để thực hiện phép tính trên từng phần tử của v4
for i in range(len(v4)):
    # Thực hiện phép tính: trừ đi 5793 và lấy modulo 256
    value = (v4[i] - 5793) % 256
    # Thêm kết quả vào danh sách v3
    v3.append(value)

# In ra kết quả cuối cùng dưới dạng các ký tự
for value in v3:
    print(chr(value), end='')

# Thêm một dòng mới sau khi in xong các ký tự
print()

```
Và ta có flag là : `FUSec{SUFnK_u0Y_wT_w0H_w0I_ED1H_0}`















