# ArcaeaMemOffsets
该项目分析了 Arcaea 内的各种基址及数据结构

## 使用
加载在程序里解析然后使用即可。

## 字段说明
### gamever
> 游戏版本

### offsets
> 所有偏移信息都在这里

 - locateMode 
> 定位模式(0=模块名称,1=特征码) 

 - locateValue 
> 由 locateMode 确定，模块名称 或 特征码的 16 进制数据 

 - memOffset
> 由 locate 获得的地址进行的偏移，读取时像这个表达式：(\\*(\\*(locate+[0]) + [1]) + [2]) 

 - lookMode 
> 读取时以什么模式读取

 - lookValue
> 由 lookModed 决定方式

| lookMode 枚举 | 格式 | 说明 |
| - | - | - |
| 0 | 空字符串 | 直接将其当成结构开始读取 |
| 1 | <每次读取字节>,<最多读取> | 按照数组形式读取数据 |

 - struct
> 数据结构偏移，结构如下：
>
> "<字段>" : "<偏移>,<(u)int,(u)short,(u)long,float,double,(string)>"

 - innerStruct
> 即额外的数据结构，与 struct 字段一致
