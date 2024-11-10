# Lab 3 报告

## 实现功能

`spawn`系统调用参照`fork`和`exec`两个系统调用，先得到调用子进程的信息，创建新的`TBC`，注意维护父子进程的关系和进程列表。
`stride`调度算法的`set_prio`系统调用，通过在`TCB`中新加入`priority`来储存优先级信息，加入`pass`来存储累加值。在每次往文物管理器中添加新任务时进行维护。

## 问答题

- 不是，8位无符号整数255加1回溢出，变成0，再次调度p2.
- 在stride调度算法中，每个进程的pass值与它的优先级成反比。如果所有进程的优先级都大于或等于2，那么每个进程的pass值将小于或等于BigStride/2。由于stride值在每次调度后会增加pass值，所以任何两个进程的stride值之差都不会超过BigStride/2。这是因为，如果一个进程的stride值达到了STRIDE_MAX（即BigStride-1），它需要至少一个其他进程的stride值达到STRIDE_MIN（即0），才能再次被调度，而这个差值就是BigStride。但由于所有进程的pass值都小于或等于BigStride/2，所以不可能有一个进程的stride值增加到BigStride，从而保证了STRIDE_MAX – STRIDE_MIN <= BigStride / 2。
- 
```Rust
use core::cmp::Ordering;

struct Stride(u64);

impl PartialOrd for Stride {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let first = self.0 as u16;
        let second = other.0 as u16;

        if first > second && (first - second) > BigStride / 2 {
            Some(Ordering::Greater)
        } else if second > first && (second - first) > BigStride / 2 {
            Some(Ordering::Less)
        } else {
            first.partial_cmp(&second)
        }
    }
}

impl PartialEq for Stride {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
```


## 荣誉准则

1. 在完成本次实验的过程（含此前学习的过程）中，我曾分别与 以下各位 就（与本次实验相关的）以下方面做过交流，还在代码中对应的位置以注释形式记录了具体的交流对象及内容：
   
2. 此外，我也参考了 以下资料 ，还在代码中对应的位置以注释形式记录了具体的参考来源及内容：
   
3. 我独立完成了本次实验除以上方面之外的所有工作，包括代码与文档。 我清楚地知道，从以上方面获得的信息在一定程度上降低了实验难度，可能会影响起评分。
   
4. 我从未使用过他人的代码，不管是原封不动地复制，还是经过了某些等价转换。 我未曾也不会向他人（含此后各届同学）复制或公开我的实验代码，我有义务妥善保管好它们。 我提交至本实验的评测系统的代码，均无意于破坏或妨碍任何计算机系统的正常运转。 我清楚地知道，以上情况均为本课程纪律所禁止，若违反，对应的实验成绩将按“-100”分计。