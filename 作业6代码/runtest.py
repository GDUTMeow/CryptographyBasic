import random
import prettytable

types = ["0", "1"]

def print_table(results):
    table = prettytable.PrettyTable()
    table.field_names = ["游程", "类型", "长度"]
    for result in results:
        table.add_row(result)
    print(table)

def runtest(array: list[int]) -> list[tuple[list[int], str, int]]:
    """游程分布检测

    Args:
        array (list[int]): 输入的生成随机数序列
    """
    results = []
    previous = array[0]
    this_array = []
    run_length = 1
    for i in array:
        if i == previous:
            run_length += 1
            this_array.append(i)
        else:
            run_type = "0" if previous == 0 else "1"
            results.append(("".join(map(str, this_array)), run_type, run_length))
            previous = i
            run_length = 1
            this_array = [i]
    # 最后一个
    run_type = "0" if previous == 0 else "1"
    results.append(("".join(map(str, this_array)), run_type, run_length))
    return results

if __name__ == "__main__":
    print("学号: 3124004333")
    array = [random.randint(0, 1) for _ in range(50)]
    print("Generated sequence:", "".join(map(str, array)))
    result = runtest(array)
    print_table(result)